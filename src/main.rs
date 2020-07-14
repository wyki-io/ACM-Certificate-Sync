use acs::{run, AcmAlbProvider, Provider, Receiver};
use async_trait::async_trait;
use std::io::prelude::*;
use std::{fs::File, path::Path};

struct DummyReceiver {}

impl Receiver for DummyReceiver {
    fn receive() -> acs::TLS {
        todo!()
    }
}

struct DummyProvider {}

#[async_trait]
impl Provider for DummyProvider {
    fn name(&self) -> String {
        String::from("Dummy")
    }
    async fn publish(&self, tls: acs::TLS) -> anyhow::Result<()> {
        let _ = tls;
        Ok(())
    }
}

fn retrieve_config() -> anyhow::Result<String> {
    let config_path_default = String::from("/config.yml");
    let config_path_env = option_env!("CONFIG_PATH");
    let config_path_str = if let Some(var) = config_path_env {
        var
    } else {
        config_path_default.as_ref()
    };
    let config_path = Path::new(&config_path_str);
    let mut content = String::new();
    let mut file = File::open(config_path)?;
    file.read_to_string(&mut content)?;
    Ok(content)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = retrieve_config()?;
    let receiver = DummyReceiver {};
    let provider = AcmAlbProvider::new(&config)?;
    run(receiver, provider).await
}
