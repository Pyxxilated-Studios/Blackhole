use std::convert::Infallible;

use serde_json::json;
use warp::{http::Response, hyper::header::CONTENT_TYPE, Filter};

use crate::statistics::STATISTICS;

#[derive(Clone)]
pub struct Server;

impl Server {
    pub async fn run(self) {
        let requests = warp::path("requests")
            .and(warp::path::end())
            .and_then(Server::requests);
        let response_time = warp::path("average")
            .and(warp::path::end())
            .and_then(Server::average);

        let api = warp::path("api").and(requests.or(response_time));

        warp::serve(api).run(([0, 0, 0, 0], 5000)).await;
    }

    async fn requests() -> Result<impl warp::Reply, Infallible> {
        match STATISTICS.read().await.requests() {
            Some(requests) => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!(requests).to_string())),
            None => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body("[]".to_string())),
        }
    }

    async fn average() -> Result<impl warp::Reply, Infallible> {
        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(json!(STATISTICS.read().await.request_time()).to_string()))
    }
}
