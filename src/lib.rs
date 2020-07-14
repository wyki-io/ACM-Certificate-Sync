#[macro_use]
extern crate log;

mod common;
mod provider;

use anyhow::anyhow;
pub use common::TLS;
pub use provider::{AcmAlbProvider, Provider};

use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, ListParams, WatchEvent},
    runtime::Informer,
    Client,
};

use futures::{StreamExt, TryStreamExt};
use k8s_openapi::ByteString;
use std::collections::BTreeMap;
use std::convert::TryFrom;

impl TryFrom<BTreeMap<String, ByteString>> for TLS {
    type Error = anyhow::Error;

    fn try_from(value: BTreeMap<String, ByteString>) -> Result<Self, Self::Error> {
        let cert = match value.get("tls.crt") {
            Some(x) => x,
            None => return Err(anyhow!("Unable to get cert from secret")),
        };
        let key = match value.get("tls.key") {
            Some(x) => x,
            None => return Err(anyhow!("Unable to get key from secret")),
        };
        let mut tls = TLS::default();
        tls.cert = match String::from_utf8(cert.0.clone()) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Unable to parse the cert from secret")),
        };
        tls.key = match String::from_utf8(key.0.clone()) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Unable to parse the key from secret")),
        };
        Ok(tls)
    }
}

pub trait Receiver {
    fn receive() -> TLS;
}

// struct KubernetesReceiver {}

// impl Receiver for KubernetesReceiver {
//     fn receive() -> acs::TLS {

//     }
// }

pub async fn run(receiver: impl Receiver, provider: impl Provider) -> anyhow::Result<()> {
    let _ = receiver;
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
            handle_secret(secret, &provider).await?;
        }
    }
}

// Check if a Certificate
pub async fn handle_secret(ev: WatchEvent<Secret>, provider: &dyn Provider) -> anyhow::Result<()> {
    let expected_type = String::from("kubernetes.io/tls");
    // dbg!("In handle_secret");
    match ev {
        WatchEvent::Added(o) | WatchEvent::Modified(o) => {
            // dbg!("In secret");
            let secret_type = o.type_.unwrap_or_default();
            if secret_type.eq(&expected_type) {
                let metadata = o.metadata.unwrap_or_default();
                let secret_namespace = metadata.namespace.unwrap_or_default();
                let secret_name = metadata.name.unwrap_or_default();
                info!("New TLS Secret : {} with type {}", secret_name, secret_type);
                match o.data {
                    Some(data) => {
                        match parse_and_publish_cert(data, provider).await {
                            Ok(_) => info!(
                                "Successfully sent secret {} from namespace {} to provider {}",
                                secret_name,
                                secret_namespace,
                                provider.name()
                            ),
                            Err(err) => error!("{}", err),
                        };
                    }
                    None => error!(
                        "{}:{} Empty data field in Kubernetes Secret",
                        secret_namespace, secret_name
                    ),
                };
            }
        }
        _ => {}
    }
    Ok(())
}

async fn parse_and_publish_cert(
    secret_data: BTreeMap<String, ByteString>,
    provider: &dyn Provider,
) -> anyhow::Result<()> {
    let tls = TLS::try_from(secret_data)?; //.with_context(|| format!("Secret to TLS conversion failed"));
    provider.publish(tls).await?;
    Ok(())
}
