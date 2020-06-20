#[macro_use]
extern crate log;

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

#[derive(Debug, Default)]
pub struct TLS {
    pub domain: String,
    pub key: String,
    pub cert: String,
    pub ca: String,
    pub chain: String,
}

impl TLS {
    pub fn new(domain: String, key: String, cert: String, ca: String, chain: String) -> Self {
        TLS {
            domain: domain,
            key: key,
            cert: cert,
            ca: ca,
            chain: chain,
        }
    }
}

impl TryFrom<BTreeMap<String, ByteString>> for TLS {
    type Error = &'static str;

    fn try_from(value: BTreeMap<String, ByteString>) -> Result<Self, Self::Error> {
        let cert = match value.get("tls.crt") {
            Some(x) => x,
            None => return Err("Unable to get cert from secret"),
        };
        let key = match value.get("tls.key") {
            Some(x) => x,
            None => return Err("Unable to get key from secret"),
        };
        let mut tls = TLS::default();
        tls.cert = match String::from_utf8(cert.0.clone()) {
            Ok(x) => x,
            Err(_) => return Err("Unable to parse the cert from secret"),
        };
        tls.key = match String::from_utf8(key.0.clone()) {
            Ok(x) => x,
            Err(_) => return Err("Unable to parse the key from secret"),
        };
        Ok(tls)
    }
}

pub struct AcmHandler {}

pub trait Provider {
    fn publish(&self, tls: TLS);
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
            handle_secret(secret, &provider)?;
        }
    }
}

// Check if a Certificate
pub fn handle_secret(ev: WatchEvent<Secret>, provider: &dyn Provider) -> anyhow::Result<()> {
    let expected_type = String::from("kubernetes.io/tls");
    // dbg!("In handle_secret");
    match ev {
        WatchEvent::Added(o) => {
            // dbg!("In secret");
            let secret_type = o.type_.unwrap_or_default();
            if secret_type.eq(&expected_type) {
                let metadata = o.metadata.unwrap_or_default();
                let secret_namespace = metadata.namespace.unwrap_or_default();
                let secret_name = metadata.name.unwrap_or_default();
                info!("New TLS Secret : {} with type {}", secret_name, secret_type);
                match o.data {
                    Some(data) => {
                        match TLS::try_from(data) {
                            Ok(tls) => provider.publish(tls),
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
