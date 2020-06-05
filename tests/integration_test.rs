use acs::run;

use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, ListParams},
    runtime::Informer,
    Client,
};

use futures::{StreamExt, TryStreamExt};
use futures_await_test::async_test;

#[tokio::test]
async fn create_certificate() {
    run().await;
}
