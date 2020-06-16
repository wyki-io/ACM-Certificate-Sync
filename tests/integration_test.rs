#[macro_use] extern crate log;
use acs::run;

use std::{thread, time};

use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, DeleteParams, ListParams, PostParams, Meta},
    runtime::Informer,
    Client,
};

// use futures::executor::spawn;
use futures::{StreamExt, TryStreamExt};
use futures_await_test::async_test;

use std::path::Path;

use serde_yaml::from_reader;

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
    let tls_secret: Secret =
        serde_yaml::from_str(file).expect("Unable to read file as YAML");
        // serde_yaml::from_reader(file).expect("Unable to convert certificate file to yaml");
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    let post_params = PostParams::default();
    match secrets.create(&post_params, &tls_secret).await {
        Ok(res) => {
            let name = Meta::name(&res);
            assert_eq!(Meta::name(&tls_secret), name);
            info!("Created {}", name);
            // wait for it..
            std::thread::sleep(std::time::Duration::from_millis(1_000));
        },
        Err(kube::Error::Api(ae)) => {
            dbg!(ae);
            ()
        }, // if you skipped delete, for instance
        Err(e) => {
            dbg!("something bad happened {}", e);
            ()
        },
    }
}

// async fn launch_app() -> thread::JoinHandle<> {
//     // async fn launch_app() {
//     thread::spawn(|| async {
//         run().await;
//     })
// }

#[tokio::test]
async fn create_certificate() {
    let client = init_client().await;
    delete_certificates(&client).await;
    // launch_app();
    tokio::spawn(run());

    let one_sec = time::Duration::from_secs(1);

    thread::sleep(one_sec);

    add_certificate(&client, include_str!("./resources/certificate.yaml")).await;
    thread::sleep(one_sec);
    // run().await;
}
