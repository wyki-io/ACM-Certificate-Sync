#[macro_use]
extern crate log;

use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, ListParams, WatchEvent},
    runtime::Informer,
    Client,
};

use futures::{StreamExt, TryStreamExt};

pub struct TLS {
    pub key: String,
    pub cert: String,
    pub ca: String,
    pub chain: String
}
pub struct AcmHandler {}

pub trait Provider {
    fn publish();
}

pub trait Receiver {
    fn receive();
}

pub async fn run() -> anyhow::Result<()> {
    std::env::set_var("RUST_LOG", "info,kube=debug");
    env_logger::init();
    info!("Hello from lib");
    let client = Client::try_default().await?;

    let secrets: Api<Secret> = Api::all(client);
    let lp = ListParams::default();
    let si = Informer::new(secrets).params(lp);

    loop {
        let mut secrets = si.poll().await?.boxed();

        while let Some(secret) = secrets.try_next().await? {
            handle_secret(secret)?;
        }
    }
}

// Check if a Certificate
pub fn handle_secret(ev: WatchEvent<Secret>) -> anyhow::Result<()> {
    let expected_type = String::from("kubernetes.io/tls");
    match ev {
        WatchEvent::Added(o) => {
            let secret_type = o.type_.unwrap_or_default();
            if secret_type.eq(&expected_type) {
                let secret_name = o.metadata.unwrap_or_default().name.unwrap_or_default();
                info!("New TLS Secret : {} with type {}", secret_name, secret_type);
            }
        }
        WatchEvent::Modified(o) => {
            let secret_type = o.type_.unwrap_or_default();
            if secret_type.eq(&expected_type) {
                let secret_name = o.metadata.unwrap_or_default().name.unwrap_or_default();
                info!(
                    "Updated TLS Secret : {} with type {}",
                    secret_name, secret_type
                );
            }
        }
        _ => {}
    }
    Ok(())
}
