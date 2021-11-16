use env_logger::{Builder, Env};
use log::error;
use std::process;

fn main() {
    if cfg!(debug_assertions) {
        Builder::from_env(Env::default().default_filter_or("debug")).init();
    } else {
        Builder::from_env(Env::default().default_filter_or("info")).init();
    }

    if let Err(e) = eis_utils::request_connection_string_from_eis_with_expiry(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            + std::time::Duration::from_secs(60),
    ) {
        error!("Application error: {}", e);

        process::exit(1);
    }
}
