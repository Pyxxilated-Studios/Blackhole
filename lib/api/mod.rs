use std::{collections::HashMap, net::Ipv6Addr};

use serde_json::json;
use tracing::error;
use warp::{
    body::BodyDeserializeError, filters::BoxedFilter, http::Response, hyper::header::CONTENT_TYPE,
    Filter, Rejection, Reply,
};

use crate::{config::Config, statistics::Statistics};

pub struct Server;

fn statistics() -> BoxedFilter<(impl Reply,)> {
    let all = warp::path("statistics")
        .and(warp::path::end())
        .map(Server::all);

    warp::path!("statistics" / String)
        .and(warp::path::end())
        .and(warp::query::<HashMap<String, String>>())
        .map(|statistic: String, params| Server::statistics(&statistic, &params))
        .or(all)
        .boxed()
}

fn config() -> BoxedFilter<(impl Reply,)> {
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
        .boxed()
}

impl Server {
    pub async fn run(self) {
        let api = warp::path("api").and(statistics().or(config()));

        warp::serve(api).run((Ipv6Addr::UNSPECIFIED, 5000)).await;
    }

    fn all() -> Box<(dyn warp::Reply + 'static)> {
        Box::new(
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!(Statistics::statistics()).to_string()),
        )
    }

    fn statistics(
        statistic: &str,
        params: &HashMap<String, String>,
    ) -> Box<(dyn warp::Reply + 'static)> {
        let from = params.get("from");
        let to = params.get("to");

        match Statistics::retrieve(&statistic.to_ascii_lowercase(), from, to) {
            Some(statistics) => Box::new(
                Response::builder()
                    .header(CONTENT_TYPE, "application/json")
                    .body(json!(statistics).to_string()),
            ),
            None => Box::new(
                Response::builder()
                    .header(CONTENT_TYPE, "application/json")
                    .body(String::from("{}")),
            ),
        }
    }

    async fn config() -> Result<Box<dyn warp::Reply>, warp::Rejection> {
        let config = Config::get(Clone::clone).await;

        Ok(Box::new(
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!(config).to_string()),
        ))
    }

    async fn update_config(body: Config) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
        match Config::set(|config| *config = body.clone()).await {
            Ok(_) => Ok(Box::new(Response::builder().body(""))),
            Err(err) => {
                error!("{err:?}");
                Ok(Box::new(Response::builder().status(500).body("")))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use pretty_assertions::assert_eq;
    use tokio::sync::Mutex;
    use warp::hyper::header::CONTENT_TYPE;

    use crate::statistics::{Statistic, Statistics};

    static WORKER: LazyLock<Mutex<bool>> = LazyLock::new(Mutex::default);

    #[tokio::test]
    async fn statistics() {
        let filter = super::statistics();

        let worker = WORKER.lock().await;
        let response = warp::test::request()
            .path("/statistics/requests")
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
        let filter = super::statistics();

        let worker = WORKER.lock().await;

        let request = crate::statistics::Request {
            ..Default::default()
        };
        let average = crate::statistics::Average {
            count: 1,
            average: 1,
        };

        Statistics::record(Statistic::Request(request.clone()));
        Statistics::record(Statistic::Average(average.clone()));

        let response = warp::test::request()
            .path("/statistics")
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
            serde_json::json!(Statistics::statistics())
                .to_string()
                .as_str()
        );

        Statistics::clear();
        drop(worker);
    }

    #[tokio::test]
    async fn requests() {
        let filter = super::statistics();

        let worker = WORKER.lock().await;
        let request = crate::statistics::Request {
            ..Default::default()
        };

        Statistics::record(Statistic::Request(request.clone()));

        let response = warp::test::request()
            .path("/statistics/requests")
            .reply(&filter)
            .await;

        Statistics::clear();
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
