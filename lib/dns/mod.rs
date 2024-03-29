use std::{
    net::IpAddr,
    str::FromStr,
    time::{Instant, SystemTime},
};

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{Record, RecordType},
    xfer::DnsResponse,
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    error::{
        ResolveError,
        ResolveErrorKind::{
            Io, Message as ResolverMessage, Msg, NoConnections, NoRecordsFound, Proto, Timeout,
        },
    },
    TokioAsyncResolver,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    cache::Cache,
    config::Config,
    filter::{rules::Rule, Filter},
    statistics::{self, Average, Statistics},
};

const fn default_port() -> u16 {
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
            Some((ip, port)) => Ok(Self {
                ip: ip.parse().map_err(|e| format!("{e}"))?,
                port: port.parse().map_err(|_| "invalid port".to_string())?,
            }),
            None => Ok(Self {
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
        );

        DnsResponse::from_message(
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
                })?,
        )
        .map_err(Into::into)
    }

    async fn create_response<R: ResponseHandler>(
        stat: &mut statistics::Request,
        request: &Request,
        response: &mut Result<DnsResponse, ResolveError>,
        mut response_handle: R,
    ) -> Result<ResponseInfo, std::io::Error> {
        let builder = MessageResponseBuilder::from_message_request(request);

        match response.as_mut() {
            Ok(response) => {
                let mut resp = response.clone().into_message();
                resp.set_id(request.id());
                stat.answers(response.answers());

                if !stat.cached
                    && resp.response_code() != ResponseCode::ServFail
                    && stat.rule.is_none()
                {
                    // We should only ever cache requests that:
                    // a) Are not already in the cache
                    // b) The response wasn't a failure (otherwise we're likely to retrieve invalid responses)
                    // c) There's no rule for the request
                    Cache::insert(&*response).await;
                }

                response_handle
                    .send_response(builder.build(
                        *resp.header(),
                        resp.answers(),
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
                        error!("{err}");
                        builder.error_msg(request.header(), ResponseCode::ServFail)
                    }
                    _ => builder.error_msg(request.header(), ResponseCode::ServFail),
                };
                response_handle.send_response(response).await
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Server {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let mut stat = statistics::Request::default();
        stat.client(request.src().ip().to_canonical().to_string())
            .question(request.query().original().name().to_string())
            .query_type(request.query().original().query_type());

        let timer = Instant::now();

        // Check the fiter first, as we need to check it anyways if it's in the cache
        // TODO: Does it make sense to also cache the filter result?
        let mut response = if let Some(rule) = Filter::check(request) {
            stat.rule(Some(rule.clone()));
            Ok(rule.apply(request))
        } else if let Some(response) = Cache::get(request).await {
            stat.cached(true);
            Ok(response)
        } else {
            self.forward(request).await
        };

        let response = Self::create_response(&mut stat, request, &mut response, response_handle)
            .await
            .unwrap_or_else(|err| {
                error!("{err}");
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
    #[inline]
    fn client(&mut self, client: String) -> &mut Self {
        self.client = client;
        self
    }

    #[inline]
    fn query_type(&mut self, query_type: RecordType) -> &mut Self {
        self.query_type = query_type;
        self
    }

    #[inline]
    fn code(&mut self, code: String) -> &mut Self {
        self.status = code;
        self
    }

    #[inline]
    fn answers(&mut self, answers: &[Record]) -> &mut Self {
        self.answers = answers.to_vec();
        self
    }

    #[inline]
    fn elapsed(&mut self, elapsed: usize) -> &mut Self {
        self.elapsed = elapsed;
        self
    }

    #[inline]
    fn question(&mut self, question: String) -> &mut Self {
        self.question = question;
        self
    }

    #[inline]
    fn rule(&mut self, rule: Option<Rule>) -> &mut Self {
        self.rule = rule;
        self
    }

    #[inline]
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
            query_type: RecordType::A,
            answers: Vec::default(),
            rule: Option::default(),
            status: String::default(),
            elapsed: 0,
            timestamp: SystemTime::now(),
            cached: false,
        }
    }
}
