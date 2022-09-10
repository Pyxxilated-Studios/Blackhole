use std::convert::Infallible;

use serde_json::json;
use warp::{http::Response, Filter};

use crate::statistics::STATS;

#[derive(Clone)]
pub struct Server;

impl Server {
    pub async fn run(self) {
        let requests = warp::path("requests")
            .and(warp::path::end())
            .and_then(Server::requests);

        let api = warp::path("api").and(requests);

        warp::serve(api).run(([0, 0, 0, 0], 5000)).await;
    }

    async fn requests() -> Result<impl warp::Reply, Infallible> {
        Ok(Response::builder()
            .header("Content-Type", "application/json")
            .body(json!(STATS.read().await.requests()).to_string()))
    }
}
