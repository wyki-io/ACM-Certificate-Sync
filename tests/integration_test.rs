#[macro_use]
extern crate log;
use acs::{run, Provider, Receiver, TLS};

use std::sync::{Arc, RwLock};

use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, DeleteParams, ListParams, Meta, PostParams},
    Client,
};

// use futures::executor::spawn;

pub struct TestReceiver {}

impl Receiver for TestReceiver {
    fn receive() -> TLS {
        todo!()
    }
}

pub struct TestProvider {
    pub tls: Arc<RwLock<TLS>>,
}

impl Provider for TestProvider {
    fn publish(&self, tls: TLS) {
        let mut tls_write = self.tls.write().unwrap();
        *tls_write = tls;
    }
}

async fn init_client() -> Client {
    Client::try_default()
        .await
        .expect("Unabled to create client")
}

async fn delete_certificates(client: &Client) {
    let secrets: Api<Secret> = Api::all(client.clone());
    let lp = ListParams::default();
    let secret_list = secrets.list(&lp).await.expect("Unable to list secrets");

    for secret in secret_list {
        if secret.clone().type_.unwrap_or_default() == "kubernetes.io/tls" {
            let namespace = Meta::namespace(&secret).unwrap_or(String::from("default"));
            println!(
                "Deleting Secret with name {} in namespace {}",
                Meta::name(&secret),
                &namespace
            );
            let secrets_namespaced: Api<Secret> = Api::namespaced(client.clone(), &namespace);
            secrets_namespaced
                .delete("test-tls", &DeleteParams::default())
                .await
                .expect("Unable to delete secret");
        }
    }
}

async fn add_certificate(client: &Client, file: &str) {
    // let path = Path::new(file);
    // dbg!(path);
    // let file = std::fs::File::open(&path).expect("Unable to open certificate file");
    let tls_secret: Secret = serde_yaml::from_str(file).expect("Unable to read file as YAML");
    // serde_yaml::from_reader(file).expect("Unable to convert certificate file to yaml");
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    let post_params = PostParams::default();
    match secrets.create(&post_params, &tls_secret).await {
        Ok(res) => {
            let name = Meta::name(&res);
            assert_eq!(Meta::name(&tls_secret), name);
            info!("Created {}", name);
            // wait for it..
            // std::thread::sleep(std::time::Duration::from_millis(1_000));
        }
        Err(kube::Error::Api(ae)) => {
            dbg!(ae);
            ()
        } // if you skipped delete, for instance
        Err(e) => {
            dbg!("something bad happened {}", e);
            ()
        }
    }
}

#[tokio::test]
async fn create_certificate() {
    let tls = Arc::new(RwLock::new(TLS::new(
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    )));
    // It currently tests with an existing Kubernetes cluster
    let receiver = TestReceiver {};
    let provider = TestProvider { tls: tls.clone() };
    tokio::spawn(run(receiver, provider));

    let client = init_client().await;
    delete_certificates(&client).await;

    let kube_secret_file_path = include_str!("./resources/certificate.yaml");
    add_certificate(&client, kube_secret_file_path).await;
    let tls_read = tls.read().unwrap();
    let kube_tls_secret: Secret =
        serde_yaml::from_str(kube_secret_file_path).expect("Unable to read file as YAML");
    assert_eq!(get_data(&kube_tls_secret, "tls.crt"), tls_read.cert);
    assert_eq!(get_data(&kube_tls_secret, "tls.key"), tls_read.key);
    delete_certificates(&client).await;
}

/// Extract data value out of a Kubernetes Secret
fn get_data(secret: &Secret, key: &str) -> String {
    let value = secret.data.as_ref().unwrap().get(key).unwrap();
    String::from_utf8(value.0.clone()).unwrap()
}
