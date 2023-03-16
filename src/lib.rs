use log::debug;
use std::time::Duration;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq)]
pub enum AuthType {
    NotSet,
    SASToken,
    SASCert,
    NestedEdgeCert,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConnType {
    NotSet,
    Device,
    Module,
}

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub auth_type: AuthType,
    pub conn_type: ConnType,
    pub connection_string: String,
    pub certificate_string: Vec<u8>,
    pub openssl_engine: String,
    pub openssl_private_key: String,
}

const IOTHUB_ENCODE_SET: &percent_encoding::AsciiSet =
    &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

pub fn request_connection_string_from_eis_with_expiry(
    expiry_since_epoch: Duration,
) -> Result<ConnectionInfo, std::io::Error> {
    if expiry_since_epoch
        <= SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid expiry, needs to be in the future.".to_string(),
        ));
    }
    let mut connection_info = ConnectionInfo {
        conn_type: ConnType::Device,
        auth_type: AuthType::NotSet,
        certificate_string: [].to_vec(),
        connection_string: "".to_string(),
        openssl_engine: "".to_string(),
        openssl_private_key: "".to_string(),
    };

    debug!("Fetching identity.");
    let identity = get_identity()?;
    debug!("Identity: {:?}", identity);

    let spec = match identity {
        aziot_identity_common::Identity::Aziot(i) => i,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Invalid identity type {:?}.", identity),
            ));
        }
    };

    let device_id: String = spec.device_id.0;
    let mut resource_uri: String = format!("{}/devices/{}", spec.hub_name, device_id);
    let mut connection_string = format!("HostName={};DeviceId={};", spec.hub_name, device_id);

    match spec.module_id {
        None => {
            connection_info.conn_type = ConnType::Device;
        }
        Some(module_id) => {
            connection_info.conn_type = ConnType::Module;
            resource_uri = format!("{}/modules/{}", resource_uri, module_id.0);
            connection_string = format!("{}ModuleId={};", connection_string, module_id.0);
        }
    }
    let auth = match spec.auth {
        Some(a) => a,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Missing auth.".to_string(),
            ));
        }
    };
    let key = match auth.key_handle {
        Some(k) => k,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Missing auth key handle.".to_string(),
            ));
        }
    };

    match auth.auth_type {
        aziot_identity_common::AuthenticationType::Sas => {
            debug!("Building SAS token.");
            let signature = build_sas(resource_uri, key, expiry_since_epoch)?;
            debug!("SAS token: {:?}", signature);

            connection_string = format!(
                "{}SharedAccessSignature=SharedAccessSignature {}",
                connection_string, signature
            );
            connection_info.connection_string = connection_string;
            connection_info.auth_type = AuthType::SASToken;
        }
        aziot_identity_common::AuthenticationType::X509 => {
            let cert_id = match auth.cert_id {
                Some(c) => c,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Missing auth cert id.".to_string(),
                    ));
                }
            };
            debug!("Fetching certificate.");
            let cert = get_certificate(&cert_id)?;
            debug!("Got certificate {:?}", cert);
            connection_info.certificate_string = cert;
            connection_string += "x509=true";
            connection_info.connection_string = connection_string;
            connection_info.auth_type = AuthType::SASCert;
            connection_info.openssl_private_key = key.0;
            if !connection_info.certificate_string.is_empty() {
                connection_info.openssl_engine = "aziot_keys".to_string();
            }
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Invalid auth type {:?}.", auth.auth_type),
            ));
        }
    }
    Ok(connection_info)
}

// SAS token generation from iot-identity-service/iotedged/src/main.rs
#[tokio::main]
async fn build_sas(
    resource_uri: String,
    key_handle: aziot_key_common::KeyHandle,
    expiry_since_epoch: Duration,
) -> Result<String, std::io::Error> {
    let connector = aziot_keyd_config::Endpoints::default().aziot_keyd;
    let key_client = aziot_key_client_async::Client::new(
        aziot_key_common_http::ApiVersion::V2020_09_01,
        connector,
        1,
    );

    let expiry = expiry_since_epoch.as_secs().to_string();

    debug!("Uri {:?}.", resource_uri);
    let resource_uri =
        percent_encoding::percent_encode(resource_uri.to_lowercase().as_bytes(), IOTHUB_ENCODE_SET)
            .to_string();
    debug!("Uri after encode: {:?}.", resource_uri);

    let sig_data = format!("{}\n{}", &resource_uri, expiry);
    debug!("Data to sign: {:?}.", sig_data);

    let signature = key_client
        .sign(
            &key_handle,
            aziot_key_common::SignMechanism::HmacSha256,
            sig_data.as_bytes(),
        )
        .await?;
    debug!("Signature (hex): {:?}.", signature);
    let signature = base64::encode(&signature);
    debug!("Signature (base64): {:?}.", signature);

    let token = url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri))
        .append_pair("sig", &signature)
        .append_pair("se", &expiry)
        .finish();
    Ok(token)
}

#[tokio::main]
async fn get_identity() -> Result<aziot_identity_common::Identity, std::io::Error> {
    let connector = aziot_identityd_config::Endpoints::default().aziot_identityd;
    let client = aziot_identity_client_async::Client::new(
        aziot_identity_common_http::ApiVersion::V2020_09_01,
        connector,
        1,
    );
    client.get_caller_identity().await
}

#[tokio::main]
async fn get_certificate(cert_id: &str) -> Result<Vec<u8>, std::io::Error> {
    let connector = aziot_certd_config::Endpoints::default().aziot_certd;
    let client = aziot_cert_client_async::Client::new(
        aziot_cert_common_http::ApiVersion::V2020_09_01,
        connector,
        1,
    );
    client.get_cert(cert_id).await
}
