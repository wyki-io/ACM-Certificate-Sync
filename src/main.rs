use warp::Filter;

#[tokio::main]
async fn main() {
    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    let index = warp::path!("health").map(|| "OK ter");

    let routes = warp::get().and(index.or(hello));

    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await;
}
