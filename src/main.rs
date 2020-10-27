#[macro_use]
extern crate log;

use anyhow::anyhow;
use cert_sync::{AcmAlbDestination, SecretSource, Source};
use std::io::prelude::*;
use std::{fs::File, path::Path};

fn retrieve_config() -> anyhow::Result<String> {
    let config_path_default = String::from("./config.yml");
    let config_path_env = option_env!("CONFIG_PATH");
    let config_path_str = if let Some(var) = config_path_env {
        var
    } else {
        config_path_default.as_ref()
    };
    info!("Config file : {}", config_path_str);
    let config_path = Path::new(&config_path_str);
    let mut content = String::new();
    let mut file = File::open(config_path)?;
    file.read_to_string(&mut content)?;
    Ok(content)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::env::set_var("RUST_LOG", "info,kube=info");
    env_logger::init();
    let config = retrieve_config()?;
    let source = SecretSource::new(&config).await?;
    let destination = AcmAlbDestination::new(&config)?;
    source.receive(&destination).await?;
    Err(anyhow!("Abort program due to unknown error"))
}
