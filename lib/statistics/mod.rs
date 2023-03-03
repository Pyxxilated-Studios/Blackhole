#[cfg(debug_assertions)]
use std::fmt::Debug;

use std::{
    hash::BuildHasherDefault,
    sync::{LazyLock, RwLock},
    time::SystemTime,
};

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace};
use trust_dns_proto::rr::Record;

use crate::filter::rules::Rule;

static STATISTICS: LazyLock<RwLock<Statistics>> = LazyLock::new(RwLock::default);

pub const REQUESTS: &str = "requests";
pub const AVERAGE_REQUEST_TIME: &str = "average";
pub const CACHE: &str = "cache";

impl Statistic {
    fn record(self, stats: &mut FxHashMap<&'static str, Statistic>) {
        match self {
            Statistic::Cache(cache) => match stats
                .entry(CACHE)
                .or_insert_with(|| Statistic::Cache(Cache::default()))
            {
                Statistic::Cache(exists) => {
                    exists.hits += cache.hits;
                    exists.misses += cache.misses;
                    exists.size += cache.size;
                }
                _ => unreachable!(),
            },
            Statistic::Count(count) => match stats
                .entry(AVERAGE_REQUEST_TIME)
                .or_insert(Statistic::Count(0))
            {
                Statistic::Count(c) => {
                    *c += count;
                }
                _ => unreachable!(),
            },
            Statistic::Average(average) => {
                match stats
                    .entry(AVERAGE_REQUEST_TIME)
                    .or_insert_with(|| Statistic::Average(Average::default()))
                {
                    Statistic::Average(av) => {
                        let count = av.count + average.count;
                        av.average =
                            (av.average * av.count + average.count * average.average) / count;
                        av.count = count;
                    }
                    _ => unreachable!(),
                }
            }
            Statistic::Request(request) => match stats
                .entry(REQUESTS)
                .or_insert_with(|| Statistic::Requests(Vec::with_capacity(128)))
            {
                Statistic::Requests(r) => r.push(request),
                _ => unreachable!(),
            },
            Statistic::Requests(requests) => match stats
                .entry(REQUESTS)
                .or_insert_with(|| Statistic::Requests(Vec::with_capacity(128)))
            {
                Statistic::Requests(r) => r.extend(requests.into_iter()),
                _ => unreachable!(),
            },
        }
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Deserialize))]
#[derive(Serialize, Clone, Default)]
pub struct Average {
    pub count: usize,
    pub average: usize,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Deserialize))]
#[derive(Serialize, Clone, Default)]
pub struct Cache {
    pub size: usize,
    pub hits: usize,
    pub misses: usize,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq))]
#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    pub client: String,
    pub question: String,
    pub answers: Vec<Record>,
    pub rule: Option<Rule>,
    pub status: String,
    pub elapsed: usize,
    pub timestamp: SystemTime,
    pub cached: bool,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug, PartialEq, Deserialize))]
#[derive(Serialize, Clone)]
pub enum Statistic {
    Count(usize),
    Average(Average),
    Request(Request),
    Requests(Vec<Request>),
    Cache(Cache),
}

pub struct Statistics {
    statistics: FxHashMap<&'static str, Statistic>,
}

impl Default for Statistics {
    fn default() -> Self {
        Statistics {
            statistics: FxHashMap::with_capacity_and_hasher(1024, BuildHasherDefault::default()),
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
        trace!("Retrieving");

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
    pub fn statistics() -> FxHashMap<&'static str, Statistic> {
        if let Ok(lock) = STATISTICS.read() {
            lock.statistics.clone()
        } else {
            FxHashMap::default()
        }
    }

    #[inline]
    pub fn clear() {
        if let Ok(mut lock) = STATISTICS.write() {
            lock.statistics = FxHashMap::default();
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
