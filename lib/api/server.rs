use std::convert::Infallible;

use serde_json::json;
use warp::{http::Response, hyper::header::CONTENT_TYPE, Filter};

use crate::statistics::STATISTICS;

#[derive(Clone)]
pub struct Server;

impl Server {
    pub async fn run(self) {
        let statistics = warp::path!("statistics" / String)
            .and(warp::path::end())
            .and_then(Server::statistics);

        let all = warp::path("statistics")
            .and(warp::path::end())
            .and_then(Server::all);

        let api = warp::path("api").and(statistics.or(all));

        warp::serve(api).run(([0, 0, 0, 0], 5000)).await;
    }

    async fn all() -> Result<impl warp::Reply, Infallible> {
        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(json!(STATISTICS.read().await.statistics()).to_string()))
    }

    async fn statistics(statistic: String) -> Result<impl warp::Reply, Infallible> {
        match STATISTICS
            .read()
            .await
            .retrieve(&statistic.to_ascii_lowercase())
        {
            Some(requests) => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!(requests).to_string())),
            None => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(String::default())),
        }
    }
}
