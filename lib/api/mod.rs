use std::{collections::HashMap, net::Ipv6Addr};

use serde::Serialize;
use tracing::error;
use warp::{
    body::BodyDeserializeError, filters::BoxedFilter, http::Response, hyper::header::CONTENT_TYPE,
    reply::json, Filter, Rejection, Reply,
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
                #[derive(Serialize)]
                struct Error {
                    reason: String,
                }

                if let Some(err) = err.find::<BodyDeserializeError>() {
                    Ok(Box::new(
                        json(&Error {
                            reason: err.to_string(),
                        })
                        .into_response(),
                    ))
                } else {
                    Err(err)
                }
            }))
        .boxed()
}

impl Server {
    #[no_coverage]
    pub async fn run(self) {
        let api = warp::path("api").and(statistics().or(config()));

        warp::serve(api).run((Ipv6Addr::UNSPECIFIED, 5000)).await;
    }

    fn all() -> Box<(dyn warp::Reply + 'static)> {
        Box::new(json(&Statistics::statistics()).into_response())
    }

    fn statistics(
        statistic: &str,
        params: &HashMap<String, String>,
    ) -> Box<(dyn warp::Reply + 'static)> {
        let from = params.get("from");
        let to = params.get("to");

        match Statistics::retrieve(&statistic.to_ascii_lowercase(), from, to) {
            Some(statistics) => Box::new(json(&statistics).into_response()),
            None => Box::new(
                Response::builder()
                    .header(CONTENT_TYPE, "application/json")
                    .body(String::from("{}")),
            ),
        }
    }

    async fn config() -> Result<Box<dyn warp::Reply>, warp::Rejection> {
        let config = Config::get(Clone::clone).await;

        Ok(Box::new(json(&config).into_response()))
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
    use rustc_hash::FxHashMap;
    use tokio::sync::Mutex;
    use warp::hyper::header::CONTENT_TYPE;

    use crate::{
        config::Config,
        statistics::{Statistic, Statistics, REQUESTS},
    };

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

        let body = String::from_utf8(response.body().to_vec());
        let body = body.unwrap();
        assert_eq!(
            serde_json::from_str::<FxHashMap<&str, Statistic>>(&body).unwrap(),
            Statistics::statistics()
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

        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key(CONTENT_TYPE));
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = String::from_utf8(response.body().to_vec());
        let body = body.unwrap();
        assert_eq!(
            serde_json::from_str::<Statistic>(&body).unwrap(),
            Statistics::retrieve(REQUESTS, None, None).unwrap()
        );

        Statistics::clear();
        drop(worker);
    }

    #[tokio::test]
    async fn config() {
        let filter = super::config();

        let worker = WORKER.lock().await;

        let _ = Config::set(|config| config.port = 10).await;
        let config = Config::get(|config| config.clone()).await;

        let response = warp::test::request().path("/config").reply(&filter).await;

        drop(worker);

        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key(CONTENT_TYPE));
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = String::from_utf8(response.body().to_vec());
        let body = body.unwrap();
        assert_eq!(serde_json::from_str::<Config>(&body).unwrap(), config);
    }

    #[tokio::test]
    async fn update_config() {
        let filter = super::config();

        let worker = WORKER.lock().await;

        *crate::config::CONFIG_FILE.write().await = Some(String::from("config.toml"));
        let mut config = Config::get(|config| config.clone()).await;
        config.port = 100;

        let response = warp::test::request()
            .path("/config")
            .method("POST")
            .json(&config)
            .reply(&filter)
            .await;

        assert_eq!(response.status(), 200);

        let response = warp::test::request().path("/config").reply(&filter).await;

        drop(worker);

        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key(CONTENT_TYPE));
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = String::from_utf8(response.body().to_vec());
        let body = body.unwrap();
        assert_eq!(serde_json::from_str::<Config>(&body).unwrap(), config);
    }
}
