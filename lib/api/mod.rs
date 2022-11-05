use std::{collections::HashMap, convert::Infallible};

use serde_json::json;
use warp::{http::Response, hyper::header::CONTENT_TYPE, Filter};

use crate::statistics::Statistics;

pub struct Server;

fn statistics() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Copy {
    warp::path!("statistics" / String)
        .and(warp::path::end())
        .and(warp::query::<HashMap<String, String>>())
        .and_then(Server::statistics)
}

fn api() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Copy {
    let all = warp::path("statistics")
        .and(warp::path::end())
        .and_then(Server::all);

    warp::path("api").and(statistics().or(all))
}

impl Server {
    pub async fn run(self) {
        warp::serve(api()).run(([0, 0, 0, 0], 5000)).await;
    }

    async fn all() -> Result<impl warp::Reply, Infallible> {
        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(json!(Statistics::statistics().await).to_string()))
    }

    async fn statistics(
        statistic: String,
        params: HashMap<String, String>,
    ) -> Result<impl warp::Reply, Infallible> {
        let from = params.get("from");
        let to = params.get("to");

        match Statistics::retrieve(&statistic.to_ascii_lowercase(), from, to).await {
            Some(requests) => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!(requests).to_string())),
            None => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(String::from("{}"))),
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use tokio::sync::Mutex;
    use warp::hyper::header::CONTENT_TYPE;

    use crate::statistics::{Statistic, Statistics};

    static WORKER: LazyLock<Mutex<u8>> = LazyLock::new(Mutex::default);

    #[tokio::test]
    async fn statistics() {
        let filter = super::api();

        let worker = WORKER.lock().await;
        let response = warp::test::request()
            .path("/api/statistics/requests")
            .reply(&filter)
            .await;
        drop(worker);

        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key(CONTENT_TYPE));
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.body(), "{}");
    }

    #[tokio::test]
    async fn all() {
        let filter = super::api();

        let worker = WORKER.lock().await;

        let request = crate::statistics::Request {
            ..Default::default()
        };
        let average = crate::statistics::Average {
            count: 1,
            average: 1,
        };

        Statistics::record(Statistic::Request(request.clone())).await;
        Statistics::record(Statistic::Average(average.clone())).await;

        let response = warp::test::request()
            .path("/api/statistics")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key(CONTENT_TYPE));
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.body(),
            serde_json::json!(Statistics::statistics().await)
                .to_string()
                .as_str()
        );

        Statistics::clear().await;
        drop(worker);
    }

    #[tokio::test]
    async fn requests() {
        let filter = super::api();

        let worker = WORKER.lock().await;
        let request = crate::statistics::Request {
            ..Default::default()
        };

        Statistics::record(Statistic::Request(request.clone())).await;

        let response = warp::test::request()
            .path("/api/statistics/requests")
            .reply(&filter)
            .await;

        Statistics::clear().await;
        drop(worker);

        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key(CONTENT_TYPE));
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.body(),
            serde_json::json!({ "Requests": [request] })
                .to_string()
                .as_str()
        );
    }
}
