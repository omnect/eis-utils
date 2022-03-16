#[macro_use]
extern crate lazy_static;
use env_logger::{Builder, Env};
use http_common;

lazy_static! {
    static ref LOG: () = if cfg!(debug_assertions) {
        Builder::from_env(Env::default().default_filter_or("debug")).init()
    } else {
        Builder::from_env(Env::default().default_filter_or("info")).init()
    };
    static ref IDENTITY_SAS: aziot_identity_common::Identity =
        aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
            hub_name: "Somehub".to_owned(),
            gateway_host: "SomeGateway".to_owned(),
            device_id: aziot_identity_common::DeviceId("SomeDeviceId".to_owned()),
            module_id: None,
            gen_id: None,
            auth: Some(aziot_identity_common::AuthenticationInfo {
                auth_type: aziot_identity_common::AuthenticationType::Sas,
                key_handle: Some(aziot_key_common::KeyHandle("SomeKey".to_owned())),
                cert_id: None,
            }),
        });
    static ref IDENTITY_CERT: aziot_identity_common::Identity =
        aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
            hub_name: "Somehub".to_owned(),
            gateway_host: "SomeGateway".to_owned(),
            device_id: aziot_identity_common::DeviceId("SomeDeviceId".to_owned()),
            module_id: None,
            gen_id: None,
            auth: Some(aziot_identity_common::AuthenticationInfo {
                auth_type: aziot_identity_common::AuthenticationType::X509,
                key_handle: Some(aziot_key_common::KeyHandle("SomeKey".to_owned())),
                cert_id: Some("test".to_owned()),
            }),
        });
    static ref IDENTITY_SAS_MOD: aziot_identity_common::Identity =
        aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
            hub_name: "Somehub".to_owned(),
            gateway_host: "SomeGateway".to_owned(),
            device_id: aziot_identity_common::DeviceId("SomeDeviceId".to_owned()),
            module_id: Some(aziot_identity_common::ModuleId("SomeModuleId".to_owned())),
            gen_id: None,
            auth: Some(aziot_identity_common::AuthenticationInfo {
                auth_type: aziot_identity_common::AuthenticationType::Sas,
                key_handle: Some(aziot_key_common::KeyHandle("SomeKey".to_owned())),
                cert_id: None,
            }),
        });
    static ref IDENTITY_CERT_MOD: aziot_identity_common::Identity =
        aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
            hub_name: "Somehub".to_owned(),
            gateway_host: "SomeGateway".to_owned(),
            device_id: aziot_identity_common::DeviceId("SomeDeviceId".to_owned()),
            module_id: Some(aziot_identity_common::ModuleId("SomeModuleId".to_owned())),
            gen_id: None,
            auth: Some(aziot_identity_common::AuthenticationInfo {
                auth_type: aziot_identity_common::AuthenticationType::X509,
                key_handle: Some(aziot_key_common::KeyHandle("SomeKey".to_owned())),
                cert_id: Some("test".to_owned()),
            }),
        });
    static ref CERT_URI_REGEX: regex::Regex =
        regex::Regex::new("^/certificates/(?P<certId>[^/]+)$")
            .expect("hard-coded regex must compile");
}

pub struct Testrunner {}

impl Testrunner {
    pub fn new(_testname: &str) -> Testrunner {
        lazy_static::initialize(&LOG);
        Testrunner {}
    }
}

impl Drop for Testrunner {
    fn drop(&mut self) {
        // place your cleanup code here
    }
}

http_common::make_service! {
    service: IdentityService,
    api_version: aziot_identity_common_http::ApiVersion,
    routes: [
        IdentityRoute,
    ],
}

http_common::make_service! {
    service: KeyService,
    api_version: aziot_key_common_http::ApiVersion,
    routes: [
        KeyRoute,
    ],
}

http_common::make_service! {
    service: CertService,
    api_version: aziot_cert_common_http::ApiVersion,
    routes: [
        CertRoute,
    ],
}

struct IdentityApi {
    identity: aziot_identity_common::Identity,
}

struct KeyApi {
    signature: http_common::ByteString,
}

struct CertApi {
    certificate: aziot_cert_common_http::Pem,
    last_cert_id: String,
}

#[derive(Clone)]
struct IdentityService {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::IdentityApi>>,
}

#[derive(Clone)]
struct KeyService {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::KeyApi>>,
}

#[derive(Clone)]
struct CertService {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::CertApi>>,
}

struct IdentityRoute {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::IdentityApi>>,
}

struct KeyRoute {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::KeyApi>>,
}

struct CertRoute {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::CertApi>>,
    cert_id: String,
}

#[async_trait::async_trait]
impl http_common::server::Route for IdentityRoute {
    type ApiVersion = aziot_identity_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_identity_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = IdentityService;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/identities/identity" {
            return None;
        }
        Some(IdentityRoute {
            api: service.api.clone(),
        })
    }
    async fn get(self) -> http_common::server::RouteResponse {
        let api = self.api.lock().await;
        let res = aziot_identity_common_http::get_module_identity::Response {
            identity: api.identity.clone(),
        };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }
    type DeleteBody = serde::de::IgnoredAny;
    type PostBody = serde::de::IgnoredAny;
    type PutBody = serde::de::IgnoredAny;
}

#[async_trait::async_trait]
impl http_common::server::Route for KeyRoute {
    type ApiVersion = aziot_key_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_key_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = KeyService;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/sign" {
            return None;
        }
        Some(KeyRoute {
            api: service.api.clone(),
        })
    }
    async fn post(
        self,
        body: Option<aziot_key_common_http::sign::Request>,
    ) -> http_common::server::RouteResponse {
        let _body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;
        let api = self.api.lock().await;
        let res = aziot_key_common_http::sign::Response {
            signature: api.signature.clone(),
        };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }
    type DeleteBody = serde::de::IgnoredAny;
    type PostBody = aziot_key_common_http::sign::Request;
    type PutBody = serde::de::IgnoredAny;
}

#[async_trait::async_trait]
impl http_common::server::Route for CertRoute {
    type ApiVersion = aziot_cert_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_cert_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = CertService;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self> {
        let captures = CERT_URI_REGEX.captures(path)?;

        let cid = &captures["certId"];
        Some(CertRoute {
            api: service.api.clone(),
            cert_id: cid.to_owned(),
        })
    }
    async fn get(self) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        api.last_cert_id = self.cert_id;
        let res = aziot_cert_common_http::get_cert::Response {
            pem: api.certificate.clone(),
        };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }
    type DeleteBody = serde::de::IgnoredAny;
    type PostBody = serde::de::IgnoredAny;
    type PutBody = serde::de::IgnoredAny;
}

const SOCKET_DEFAULT_PERMISSION: u32 = 0o660;

async fn start_identity_service(
    mock_identity: aziot_identity_common::Identity,
) -> Result<IdentityService, std::io::Error> {
    log::debug!("Starting identity service...");
    let config_path: std::path::PathBuf = "tests/identity-config.toml".into();
    let config: toml::Value = match config_common::read_config(&config_path, None) {
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Could not read config {}: {:?}",
                    config_path.to_string_lossy(),
                    e
                ),
            ));
        }
        Ok(s) => s,
    };
    let settings: aziot_identityd_config::Settings = serde::Deserialize::deserialize(config)?;

    let connector = settings.endpoints.aziot_identityd.clone();

    let api = IdentityApi {
        identity: mock_identity,
    };
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));
    let server = IdentityService { api };

    log::debug!("Starting identity server...");

    let mut incoming = match connector.incoming(SOCKET_DEFAULT_PERMISSION, None).await {
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Could not create incoming connector: {:?}", e),
            ));
        }
        Ok(s) => s,
    };

    // Channel to gracefully shut down the server. It's currently not used.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let service = incoming.serve(server.clone(), shutdown_rx).await;
    match service {
        Err(e) => {
            log::error!("Creating incoming connector for identity failed: {:?}", e);
        }
        Ok(_s) => _s,
    };
    log::debug!("Stopped identity server.");
    Ok(server)
}

async fn start_key_service() -> Result<(), std::io::Error> {
    log::debug!("Starting key service...");
    let config_path: std::path::PathBuf = "tests/key-config.toml".into();
    let config: toml::Value = match config_common::read_config(&config_path, None) {
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Could not read config {}: {:?}",
                    config_path.to_string_lossy(),
                    e
                ),
            ));
        }
        Ok(s) => s,
    };
    let settings: aziot_keyd_config::Config = serde::Deserialize::deserialize(config)?;

    let connector = settings.endpoints.aziot_keyd.clone();

    let api = KeyApi {
        signature: http_common::ByteString {
            0: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        },
    };
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));
    let server = KeyService { api };

    log::debug!("Starting key server...");

    let mut incoming = match connector.incoming(SOCKET_DEFAULT_PERMISSION, None).await {
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Could not create incoming connector: {:?}", e),
            ));
        }
        Ok(s) => s,
    };

    // Channel to gracefully shut down the server. It's currently not used.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let service = incoming.serve(server, shutdown_rx).await;
    match service {
        Err(e) => {
            log::error!("Creating incoming connector for key failed: {:?}", e);
        }
        Ok(_s) => _s,
    };
    log::debug!("Stopped key server.");
    Ok(())
}

async fn start_cert_service() -> Result<(), std::io::Error> {
    log::debug!("Starting cert service...");
    let config_path: std::path::PathBuf = "tests/cert-config.toml".into();
    let config: toml::Value = match config_common::read_config(&config_path, None) {
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Could not read config {}: {:?}",
                    config_path.to_string_lossy(),
                    e
                ),
            ));
        }
        Ok(s) => s,
    };
    let settings: aziot_certd_config::Config = serde::Deserialize::deserialize(config)?;

    let connector = settings.endpoints.aziot_certd.clone();

    let api = CertApi {
        certificate: aziot_cert_common_http::Pem {
            0: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        },
        last_cert_id: "INVALID".to_owned(),
    };
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));
    let server = CertService { api };

    log::debug!("Starting cert server...");

    let mut incoming = match connector.incoming(SOCKET_DEFAULT_PERMISSION, None).await {
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Could not create incoming connector: {:?}", e),
            ));
        }
        Ok(s) => s,
    };

    // Channel to gracefully shut down the server. It's currently not used.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let service = incoming.serve(server, shutdown_rx).await;
    match service {
        Err(e) => {
            log::error!("Creating incoming connector for cert failed: {:?}", e);
        }
        Ok(_s) => _s,
    };
    log::debug!("Stopped cert server.");
    Ok(())
}

#[test]
#[ignore]
fn check_request_connection_string_from_eis_with_expiry_with_sas_token() {
    let _tr =
        Testrunner::new("check_request_connection_string_from_eis_with_expiry_with_sas_token");

    log::debug!("test starting");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _join_handle = rt.block_on(async {
        let _identity_handle = tokio::task::spawn(start_identity_service((*IDENTITY_SAS).clone()));
        log::debug!("started identity service");
    });
    let rt2 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle2 = rt2.block_on(async {
        let _key_handle = tokio::task::spawn(start_key_service());
        log::debug!("started key service");
    });
    let rt3 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle3 = rt3.block_on(async {
        let _cert_handle = tokio::task::spawn(start_cert_service());
        log::debug!("started cert service");
    });
    let expire = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        + std::time::Duration::new(60, 0);
    std::thread::sleep(std::time::Duration::from_millis(2000));
    let result =
        eis_utils::request_connection_string_from_eis_with_expiry(expire).expect("Success");
    assert!(result.auth_type == eis_utils::AuthType::SASToken);
    assert!(result.conn_type == eis_utils::ConnType::Device);
    assert_eq!(result.connection_string, format!("HostName=Somehub;DeviceId=SomeDeviceId;SharedAccessSignature=SharedAccessSignature sr=somehub/devices/somedeviceid&sig=AQIDBAUGBwg%3D&se={}", expire.as_secs()));
    assert_eq!(result.certificate_string.len(), 0);
    assert_eq!(result.openssl_engine.len(), 0);
    assert_eq!(result.openssl_private_key.len(), 0);

    log::info!("{:?}", result);
}

#[test]
#[ignore]
fn check_request_connection_string_from_eis_with_expiry_with_cert() {
    let _tr = Testrunner::new("check_request_connection_string_from_eis_with_expiry_with_cert");

    log::debug!("test starting");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _join_handle = rt.block_on(async {
        let _identity_handle = tokio::task::spawn(start_identity_service((*IDENTITY_CERT).clone()));
        log::debug!("started identity service");
    });
    let rt2 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle2 = rt2.block_on(async {
        let _key_handle = tokio::task::spawn(start_key_service());
        log::debug!("started key service");
    });
    let rt3 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle3 = rt3.block_on(async {
        let _cert_handle = tokio::task::spawn(start_cert_service());
        log::debug!("started cert service");
    });
    let expire = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        + std::time::Duration::new(60, 0);
    std::thread::sleep(std::time::Duration::from_millis(2000));
    let result =
        eis_utils::request_connection_string_from_eis_with_expiry(expire).expect("Success");
    assert!(result.auth_type == eis_utils::AuthType::SASCert);
    assert!(result.conn_type == eis_utils::ConnType::Device);
    assert_eq!(
        result.connection_string,
        format!("HostName=Somehub;DeviceId=SomeDeviceId;x509=true")
    );
    assert_eq!(result.certificate_string.len(), 8);
    assert_eq!(result.openssl_engine, "aziot_keys");
    assert_eq!(result.openssl_private_key, "SomeKey");

    log::info!("{:?}", result);
}

#[test]
#[ignore]
fn check_request_connection_string_from_eis_with_expiry_with_sas_token_and_mod() {
    let _tr = Testrunner::new(
        "check_request_connection_string_from_eis_with_expiry_with_sas_token_and_mod",
    );

    log::debug!("test starting");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _join_handle = rt.block_on(async {
        let _identity_handle =
            tokio::task::spawn(start_identity_service((*IDENTITY_SAS_MOD).clone()));
        log::debug!("started identity service");
    });
    let rt2 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle2 = rt2.block_on(async {
        let _key_handle = tokio::task::spawn(start_key_service());
        log::debug!("started key service");
    });
    let rt3 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle3 = rt3.block_on(async {
        let _cert_handle = tokio::task::spawn(start_cert_service());
        log::debug!("started cert service");
    });
    let expire = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        + std::time::Duration::new(60, 0);
    std::thread::sleep(std::time::Duration::from_millis(2000));
    let result =
        eis_utils::request_connection_string_from_eis_with_expiry(expire).expect("Success");
    assert!(result.auth_type == eis_utils::AuthType::SASToken);
    assert!(result.conn_type == eis_utils::ConnType::Module);
    assert_eq!(result.connection_string, format!("HostName=Somehub;DeviceId=SomeDeviceId;ModuleId=SomeModuleId;SharedAccessSignature=SharedAccessSignature sr=somehub/devices/somedeviceid/modules/somemoduleid&sig=AQIDBAUGBwg%3D&se={}", expire.as_secs()));
    assert_eq!(result.certificate_string.len(), 0);
    assert_eq!(result.openssl_engine.len(), 0);
    assert_eq!(result.openssl_private_key.len(), 0);

    log::info!("{:?}", result);
}

#[test]
#[ignore]
fn check_request_connection_string_from_eis_with_expiry_with_cert_and_mod() {
    let _tr =
        Testrunner::new("check_request_connection_string_from_eis_with_expiry_with_cert_and_mod");

    log::debug!("test starting");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _join_handle = rt.block_on(async {
        let _identity_handle =
            tokio::task::spawn(start_identity_service((*IDENTITY_CERT_MOD).clone()));
        log::debug!("started identity service");
    });
    let rt2 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle2 = rt2.block_on(async {
        let _key_handle = tokio::task::spawn(start_key_service());
        log::debug!("started key service");
    });
    let rt3 = tokio::runtime::Runtime::new().unwrap();
    let _join_handle3 = rt3.block_on(async {
        let _cert_handle = tokio::task::spawn(start_cert_service());
        log::debug!("started cert service");
    });
    let expire = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        + std::time::Duration::new(60, 0);
    std::thread::sleep(std::time::Duration::from_millis(2000));
    let result =
        eis_utils::request_connection_string_from_eis_with_expiry(expire).expect("Success");
    assert!(result.auth_type == eis_utils::AuthType::SASCert);
    assert!(result.conn_type == eis_utils::ConnType::Module);
    assert_eq!(
        result.connection_string,
        format!("HostName=Somehub;DeviceId=SomeDeviceId;ModuleId=SomeModuleId;x509=true")
    );
    assert_eq!(result.certificate_string.len(), 8);
    assert_eq!(result.openssl_engine, "aziot_keys");
    assert_eq!(result.openssl_private_key, "SomeKey");

    log::info!("{:?}", result);
}
