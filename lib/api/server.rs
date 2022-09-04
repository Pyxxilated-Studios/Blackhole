use std::convert::Infallible;

use serde_json::json;
use warp::{http::Response, Filter};

use crate::api;

#[derive(Clone)]
pub struct Server {
    context: api::Context,
}

fn with_context(
    context: api::Context,
) -> impl Filter<Extract = (api::Context,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || context.clone())
}

impl Server {
    pub fn with_context(context: api::Context) -> Server {
        Server { context }
    }

    pub async fn run(self) {
        let requests = warp::path("requests")
            .and(warp::path::end())
            .and(with_context(self.context.clone()))
            .and_then(Server::requests);

        let api = warp::path("api").and(requests);

        warp::serve(api).run(([0, 0, 0, 0], 5000)).await;
    }

    async fn requests(ctx: api::Context) -> Result<impl warp::Reply, Infallible> {
        Ok(Response::builder()
            .header("Content-Type", "application/json")
            .body(
                json!(ctx
                    .server
                    .requests()
                    .read()
                    .await
                    .iter()
                    .collect::<Vec<(&String, &usize)>>())
                .to_string(),
            ))
    }
}
