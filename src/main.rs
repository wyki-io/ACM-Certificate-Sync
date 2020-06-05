use acs::run;

use futures::{StreamExt, TryStreamExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}
