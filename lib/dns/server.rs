use std::{
    net::IpAddr,
    str::FromStr,
    time::{Instant, SystemTime},
};

use serde::{Deserialize, Serialize};
use tracing::error;
use trust_dns_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::Record,
    xfer::DnsResponse,
};
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    error::{
        ResolveError,
        ResolveErrorKind::{
            Io, Message as ResolverMessage, Msg, NoConnections, NoRecordsFound, Proto, Timeout,
        },
    },
    TokioAsyncResolver,
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

use crate::{
    cache::Cache,
    config::Config,
    filter::{rules::Rule, Filter},
    statistics::{self, Average, Statistics},
};

fn default_port() -> u16 {
    53
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub ip: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl FromStr for Upstream {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.split_once(':') {
            Some((ip, port)) => Ok(Upstream {
                ip: ip.parse().map_err(|e| format!("{e}"))?,
                port: port.parse().map_err(|_| "invalid port".to_string())?,
            }),
            None => Ok(Upstream {
                ip: value.parse().map_err(|e| format!("{e}"))?,
                port: default_port(),
            }),
        }
    }
}

pub struct Server;

impl Server {
    async fn forward(&self, request: &Request) -> Result<DnsResponse, ResolveError> {
        let nameservers = Config::get(|config| config.upstreams.clone())
            .await
            .iter()
            .fold(
                NameServerConfigGroup::default(),
                |mut groups, &Upstream { ip, port }| {
                    groups.merge(NameServerConfigGroup::from_ips_clear(&[ip], port, true));
                    groups
                },
            );

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::from_parts(None, vec![], nameservers),
            ResolverOpts::default(),
        )?;

        resolver
            .lookup(request.query().name(), request.query().query_type())
            .await
            .map(|response| {
                Message::new()
                    .set_header(
                        *request
                            .header()
                            .clone()
                            .set_answer_count(
                                u16::try_from(response.records().len()).unwrap_or_default(),
                            )
                            .set_message_type(MessageType::Response)
                            .set_response_code(ResponseCode::NoError),
                    )
                    .add_answers(response.records().to_vec())
                    .add_query(response.query().clone())
                    .clone()
                    .into()
            })
    }
}

#[async_trait::async_trait]
impl RequestHandler for Server {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let mut stat = statistics::Request::default();
        stat.client(request.src().ip().to_canonical().to_string())
            .question(request.query().original().name().to_string());

        let timer = Instant::now();

        // Check the fiter first, as we need to check it anyways if it's in the cache
        // TODO: Does it make sense to also cache the filter result?
        let response = if let Some(rule) = Filter::check(request) {
            stat.rule(Some(rule.clone()));
            Ok(rule.apply(request))
        } else if let Some(response) = Cache::get(request).await {
            stat.cached(true);
            Ok(response)
        } else {
            self.forward(request).await
        };

        let builder = MessageResponseBuilder::from_message_request(request);

        let response = match response {
            Ok(mut response) => {
                response.set_id(request.id());
                stat.answers(response.answers());

                if !stat.cached
                    && response.response_code() != ResponseCode::ServFail
                    && stat.rule.is_none()
                {
                    // We should only ever cache requests that:
                    // a) Are not already in the cache
                    // b) The response wasn't a failure (otherwise we're likely to retrieve invalid responses)
                    // c) There's no rule for the request
                    Cache::insert(&response).await;
                }

                response_handle
                    .send_response(builder.build(
                        *response.header(),
                        response.answers(),
                        request.name_servers(),
                        &[],
                        request.additionals(),
                    ))
                    .await
            }
            Err(err) => {
                let response = match err.kind() {
                    NoRecordsFound { .. } => {
                        builder.error_msg(request.header(), ResponseCode::NXDomain)
                    }
                    ResolverMessage(_) | Msg(_) | NoConnections | Io(_) | Proto(_) | Timeout => {
                        builder.error_msg(request.header(), ResponseCode::ServFail)
                    }
                    _ => builder.error_msg(request.header(), ResponseCode::ServFail),
                };
                error!("{:#?}", err);
                response_handle.send_response(response).await
            }
        }
        .unwrap_or_else(|err| {
            error!("{:#?}", err);
            (*request.header()).into()
        });

        let elapsed = timer.elapsed().as_nanos() as usize;

        stat.elapsed(elapsed)
            .code(response.response_code().to_string());

        Statistics::record(crate::statistics::Statistic::Request(stat));
        Statistics::record(crate::statistics::Statistic::Average(Average {
            count: 1,
            average: elapsed,
        }));

        response
    }
}

impl statistics::Request {
    fn client(&mut self, client: String) -> &mut Self {
        self.client = client;
        self
    }

    fn code(&mut self, code: String) -> &mut Self {
        self.status = code;
        self
    }

    fn answers(&mut self, answers: &[Record]) -> &mut Self {
        self.answers = answers.to_vec();
        self
    }

    fn elapsed(&mut self, elapsed: usize) -> &mut Self {
        self.elapsed = elapsed;
        self
    }

    fn question(&mut self, question: String) -> &mut Self {
        self.question = question;
        self
    }

    fn rule(&mut self, rule: Option<Rule>) -> &mut Self {
        self.rule = rule;
        self
    }

    fn cached(&mut self, cached: bool) -> &mut Self {
        self.cached = cached;
        self
    }
}

impl Default for statistics::Request {
    fn default() -> Self {
        Self {
            client: String::default(),
            question: String::default(),
            answers: Vec::default(),
            rule: Option::default(),
            status: String::default(),
            elapsed: 0,
            timestamp: SystemTime::now(),
            cached: false,
        }
    }
}
