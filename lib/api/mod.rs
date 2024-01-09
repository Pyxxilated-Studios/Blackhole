use std::net::Ipv6Addr;

use prometheus_client::encoding::text::encode;
use serde::{Deserialize, Serialize};
use tokio::sync::watch::Receiver;
use warp::{
    body::BodyDeserializeError, filters::BoxedFilter, http::Response, hyper::header::CONTENT_TYPE,
    reply::json, Filter, Rejection, Reply,
};

use crate::metrics::REGISTRY;

#[derive(Serialize, Deserialize)]
struct Timespan {
    from: Option<usize>,
    to: Option<usize>,
}

pub struct Server;

impl Server {
    /// Run the API
    ///
    /// # Errors
    /// This may error out in the case that the port we're trying to bind to is already in
    /// use.
    ///
    #[coverage(off)]
    pub async fn run(self, mut shutdown_signal: Receiver<bool>) -> Result<(), warp::Error> {
        let api = warp::path("api")
            .and(
                Self::statistics()
                    .or(Self::filters())
                    .or(Self::config())
                    .or(Self::metrics()),
            )
            .recover(|err: Rejection| async move {
                #[derive(Serialize)]
                struct Error {
                    reason: String,
                }

                err.find::<BodyDeserializeError>().map_or_else(
                    || {
                        tracing::error!("{err:#?}");

                        Ok(warp::reply::with_status(
                            json(&Error {
                                reason: format!("{err:#?}"),
                            }),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    },
                    |err| {
                        Ok::<_, std::convert::Infallible>(warp::reply::with_status(
                            json(&Error {
                                reason: err.to_string(),
                            }),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    },
                )
            });

        warp::serve(api)
            .try_bind_with_graceful_shutdown((Ipv6Addr::UNSPECIFIED, 5000), async move {
                let _ = shutdown_signal.changed().await;
            })?
            .1
            .await;

        Ok(())
    }

    fn statistics() -> BoxedFilter<(impl Reply,)> {
        warp::path!("statistics" / String)
            .and(warp::query::<Timespan>())
            .map(|statistic: String, params| statistics::statistic(&statistic, &params))
            .or(warp::path("statistics").map(statistics::all))
            .boxed()
    }

    fn config() -> BoxedFilter<(impl Reply,)> {
        warp::path("config")
            .and(warp::get().and_then(config::get))
            .or(warp::path("config")
                .and(warp::post())
                .and(warp::body::json())
                .and_then(config::update))
            .boxed()
    }

    fn metrics() -> BoxedFilter<(impl Reply,)> {
        warp::path("metrics")
            .and(warp::get())
            .map(|| {
                let mut response = Response::<String>::default();
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    warp::http::header::HeaderValue::from_static(
                        "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    ),
                );
                encode(response.body_mut(), &REGISTRY.read().unwrap()).unwrap();
                response
            })
            .boxed()
    }

    fn filters() -> BoxedFilter<(impl Reply,)> {
        warp::path("filters")
            .and(warp::get().and_then(filters::all))
            .or(warp::path("filters")
                .and(warp::post())
                .and(warp::body::json())
                .and_then(filters::add))
            .or(warp::path("filters")
                .and(warp::delete())
                .and(warp::body::json())
                .and_then(filters::remove))
            .boxed()
    }
}

mod statistics {
    use ahash::AHashMap;
    use warp::{
        http::Response,
        reply::{json, Reply},
    };

    use crate::statistics::Statistics;

    use super::Timespan;

    pub(super) fn all() -> Response<warp::hyper::Body> {
        json(&Statistics::statistics()).into_response()
    }

    pub(super) fn statistic(statistic: &str, params: &Timespan) -> Response<warp::hyper::Body> {
        Statistics::retrieve(&statistic.to_ascii_lowercase(), params.from, params.to).map_or_else(
            || json(&AHashMap::<&str, String>::default()).into_response(),
            |statistics| json(&statistics).into_response(),
        )
    }
}

mod config {
    use warp::{
        http::Response,
        reply::{json, Reply},
    };

    use crate::{config::Config, filter};

    pub(super) async fn get() -> Result<Response<warp::hyper::Body>, warp::Rejection> {
        let mut config = Config::get(Clone::clone).await;
        config.filters = filter::Filter::lists();

        Ok(json(&config).into_response())
    }

    pub(super) async fn update(
        body: Config,
    ) -> Result<Response<warp::hyper::Body>, warp::Rejection> {
        #[cfg(debug_assertions)]
        tracing::debug!("Updating Config: {body:#?}");

        Config::set(|config| *config = body.clone())
            .await
            .map(|()| Response::default())
            .map_err(warp::reject::custom)
    }
}

mod filters {
    use warp::{
        http::Response,
        reply::{json, Reply},
    };

    use crate::config::Config;

    pub(super) async fn all() -> Result<Response<warp::hyper::Body>, warp::Rejection> {
        let filters = Config::get(|config| config.filters.clone()).await;
        Ok(json(&filters).into_response())
    }

    pub(super) async fn add(
        filter: crate::filter::List,
    ) -> Result<Response<warp::hyper::Body>, warp::Rejection> {
        #[cfg(debug_assertions)]
        tracing::debug!("Adding filter list: {filter:#?}");

        Config::set(|config| {
            config.filters.insert(filter.clone());
        })
        .await
        .map(|()| Response::default())
        .map_err(warp::reject::custom)
    }

    pub(super) async fn remove(
        filter: crate::filter::List,
    ) -> Result<Response<warp::hyper::Body>, warp::Rejection> {
        #[cfg(debug_assertions)]
        tracing::debug!("Removing filter list: {filter:#?}");

        Config::set(|config| {
            config.filters.remove(&filter);
        })
        .await
        .map(|()| Response::default())
        .map_err(warp::reject::custom)
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use ahash::AHashMap;
    use pretty_assertions::assert_eq;
    use tokio::sync::Mutex;
    use warp::hyper::header::CONTENT_TYPE;

    use crate::{
        config::Config,
        statistics::{Statistic, Statistics, REQUESTS},
    };

    static WORKER: LazyLock<Mutex<bool>> = LazyLock::new(Mutex::default);

    #[tokio::test]
    async fn statistics() {
        let filter = super::Server::statistics();

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
        let filter = super::Server::statistics();

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
            serde_json::from_str::<AHashMap<&str, Statistic>>(&body).unwrap(),
            Statistics::statistics()
        );

        Statistics::clear();
        drop(worker);
    }

    #[tokio::test]
    async fn requests() {
        let filter = super::Server::statistics();

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
        let filter = super::Server::config();

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
        let filter = super::Server::config();

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
