#[cfg(debug_assertions)]
use std::fmt::Debug;

use std::{
    sync::{LazyLock, RwLock},
    time::SystemTime,
};

use ahash::AHashMap;
use hickory_proto::rr::{Record, RecordType};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::{
    filter::rules::{Kind, Rule},
    metrics,
};

static STATISTICS: LazyLock<RwLock<Statistics>> = LazyLock::new(RwLock::default);

pub const REQUESTS: &str = "requests";
pub const AVERAGE_REQUEST_TIME: &str = "average";
pub const CACHE: &str = "cache";

impl Statistic {
    fn record(self, stats: &mut AHashMap<&'static str, Self>) {
        match self {
            Self::Cache(cache) => match stats
                .entry(CACHE)
                .or_insert_with(|| Self::Cache(Cache::default()))
            {
                Self::Cache(exists) => {
                    metrics::CACHE
                        .get_or_create(&metrics::Cache {
                            hit: (cache.hits > 0).to_string(),
                        })
                        .inc();

                    exists.hits += cache.hits;
                    exists.misses += cache.misses;
                    exists.size += cache.size;
                }
                _ => unreachable!(),
            },
            Self::Count(count) => match stats.entry(AVERAGE_REQUEST_TIME).or_insert(Self::Count(0))
            {
                Self::Count(c) => {
                    *c += count;
                }
                _ => unreachable!(),
            },
            Self::Average(average) => {
                match stats
                    .entry(AVERAGE_REQUEST_TIME)
                    .or_insert_with(|| Self::Average(Average::default()))
                {
                    Self::Average(av) => {
                        let count = av.count + average.count;
                        av.average =
                            (av.average * av.count + average.count * average.average) / count;
                        av.count = count;

                        metrics::DURATION.observe(average.average as f64);
                    }
                    _ => unreachable!(),
                }
            }
            Self::Request(request) => match stats
                .entry(REQUESTS)
                .or_insert_with(|| Self::Requests(Vec::with_capacity(128)))
            {
                Self::Requests(r) => {
                    metrics::REQUESTS
                        .get_or_create(&metrics::Request {
                            client: request.client.clone(),
                            question: request.question.clone(),
                            r#type: request.query_type.to_string(),
                            rule: request
                                .rule
                                .as_ref()
                                .map_or_else(|| String::from("None"), |rule| rule.kind.to_string()),
                        })
                        .inc();

                    if request
                        .rule
                        .as_ref()
                        .map_or(false, |rule| rule.kind == Kind::Deny)
                    {
                        metrics::BLOCKED.inc();
                    }

                    r.push(request);
                }
                _ => unreachable!(),
            },
            Self::Requests(requests) => match stats
                .entry(REQUESTS)
                .or_insert_with(|| Self::Requests(Vec::with_capacity(128)))
            {
                Self::Requests(r) => {
                    for request in &requests {
                        metrics::REQUESTS
                            .get_or_create(&metrics::Request {
                                client: request.client.clone(),
                                question: request.question.clone(),
                                r#type: request.query_type.to_string(),
                                rule: request.rule.as_ref().map_or_else(
                                    || String::from("None"),
                                    |rule| rule.kind.to_string(),
                                ),
                            })
                            .inc();
                    }
                    r.extend(requests);
                }
                _ => unreachable!(),
            },
        }
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Eq, Deserialize))]
#[derive(Serialize, Clone, Default)]
pub struct Average {
    pub count: usize,
    pub average: usize,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Eq, Deserialize))]
#[derive(Serialize, Clone, Default)]
pub struct Cache {
    pub size: usize,
    pub hits: usize,
    pub misses: usize,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Eq))]
#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    pub client: String,
    pub question: String,
    pub query_type: RecordType,
    pub answers: Vec<Record>,
    pub rule: Option<Rule>,
    pub status: String,
    pub elapsed: usize,
    pub timestamp: SystemTime,
    pub cached: bool,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Eq, Deserialize))]
#[derive(Serialize, Clone)]
pub enum Statistic {
    Count(usize),
    Average(Average),
    Request(Request),
    Requests(Vec<Request>),
    Cache(Cache),
}

pub struct Statistics {
    statistics: AHashMap<&'static str, Statistic>,
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            statistics: AHashMap::with_capacity(1024),
        }
    }
}

impl Statistics {
    #[inline]
    pub fn record(value: Statistic) {
        if let Ok(mut lock) = STATISTICS.write() {
            value.record(&mut lock.statistics);
        }
    }

    #[instrument]
    pub fn retrieve(
        statistic: &str,
        from: Option<&String>,
        to: Option<&String>,
    ) -> Option<Statistic> {
        debug!("Retrieving statistics");

        match &STATISTICS.read().unwrap().statistics.get(statistic) {
            Some(Statistic::Requests(ref requests)) => {
                let len = requests.len();

                let from = from.map_or(0, |from| from.parse().unwrap_or_default());
                let to = to.map_or(len, |to| to.parse().unwrap_or(len));

                let mut requests = requests
                    .iter()
                    .skip(from)
                    .take(to - from)
                    .cloned()
                    .collect::<Vec<_>>();

                requests.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

                Some(Statistic::Requests(requests))
            }
            stat => stat.cloned(),
        }
    }

    #[inline]
    pub fn statistics() -> AHashMap<&'static str, Statistic> {
        STATISTICS
            .read()
            .map(|statistics| statistics.statistics.clone())
            .unwrap_or_default()
    }

    #[inline]
    pub fn clear() {
        if let Ok(mut lock) = STATISTICS.write() {
            lock.statistics = AHashMap::default();
        }
    }

    pub fn modify<F>(statistic: &str, f: F)
    where
        F: FnOnce(&mut Statistic),
    {
        if let Ok(mut lock) = STATISTICS.write() {
            lock.statistics
                .get_mut(statistic)
                .map(f)
                .unwrap_or_default();
        }
    }
}
