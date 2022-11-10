use std::{collections::HashMap, convert::Infallible, net::Ipv6Addr};

use serde_json::json;
use tracing::error;
use warp::{
    body::BodyDeserializeError, http::Response, hyper::header::CONTENT_TYPE, Filter, Rejection,
};

use crate::{config::Config, statistics::Statistics};

pub struct Server;

fn statistics() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Copy {
    warp::path!("statistics" / String)
        .and(warp::path::end())
        .and(warp::query::<HashMap<String, String>>())
        .and_then(Server::statistics)
}

fn config() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Copy {
    warp::path!("config")
        .and(warp::path::end())
        .and(warp::get().and_then(Server::config))
        .or(warp::post()
            .and(warp::body::json())
            .and_then(Server::update_config)
            .recover(|err: Rejection| async {
                if let Some(err) = err.find::<BodyDeserializeError>() {
                    Ok(Response::builder()
                        .status(400)
                        .body(json!({ "reason": err.to_string() }).to_string()))
                } else {
                    Err(err)
                }
            }))
}

fn api() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Copy {
    let all = warp::path("statistics")
        .and(warp::path::end())
        .and_then(Server::all);

    warp::path("api").and(statistics().or(config()).or(all))
}

impl Server {
    pub async fn run(self) {
        warp::serve(api()).run((Ipv6Addr::UNSPECIFIED, 5000)).await;
    }

    async fn all() -> Result<impl warp::Reply, Rejection> {
        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(json!(Statistics::statistics().await).to_string()))
    }

    async fn statistics(
        statistic: String,
        params: HashMap<String, String>,
    ) -> Result<impl warp::Reply, Rejection> {
        let from = params.get("from");
        let to = params.get("to");

        match Statistics::retrieve(&statistic.to_ascii_lowercase(), from, to).await {
            Some(statistics) => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!(statistics).to_string())),
            None => Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(String::from("{}"))),
        }
    }

    async fn config() -> Result<impl warp::Reply, Rejection> {
        let config = Config::get(Clone::clone).await;

        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(json!(config).to_string()))
    }

    async fn update_config(body: Config) -> Result<impl warp::Reply, Infallible> {
        println!("Received body: {body:?}");

        match Config::set(|config| *config = body.clone()).await {
            Ok(_) => Ok(Response::builder().body("")),
            Err(err) => {
                error!("{err:?}");
                Ok(Response::builder().status(500).body(""))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use std::sync::LazyLock;

    use tokio::sync::Mutex;
    use warp::hyper::header::CONTENT_TYPE;

    use crate::statistics::{Statistic, Statistics};

    static WORKER: LazyLock<Mutex<bool>> = LazyLock::new(Mutex::default);

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
