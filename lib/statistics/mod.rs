use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::{
    dns::Record as Answer,
    dns::{question::Question, ResultCode},
    filter::Rule,
};

static STATISTICS: LazyLock<Arc<RwLock<Statistics>>> = LazyLock::new(Arc::default);

pub const REQUEST: &str = "requests";
pub const AVERAGE_REQUEST_TIME: &str = "average";
pub const CACHE: &str = "cache";

impl Statistic {
    fn record(self, stats: &mut HashMap<&'static str, Statistic>) {
        match self {
            Statistic::Cache(cache) => match stats
                .entry(CACHE)
                .or_insert(Statistic::Cache(Cache::default()))
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
                .entry(REQUEST)
                .or_insert(Statistic::Requests(Vec::new()))
            {
                Statistic::Requests(r) => r.push(request),
                _ => unreachable!(),
            },
            Statistic::Requests(requests) => match stats
                .entry(REQUEST)
                .or_insert(Statistic::Requests(Vec::new()))
            {
                Statistic::Requests(r) => r.extend(requests.into_iter()),
                _ => unreachable!(),
            },
        }
    }
}

#[derive(Serialize, Clone, Default)]
pub struct Average {
    pub count: usize,
    pub average: usize,
}

#[derive(Serialize, Clone, Default)]
pub struct Cache {
    pub size: usize,
    pub hits: usize,
    pub misses: usize,
}

#[derive(Serialize, Clone, Default)]
pub struct Request {
    pub client: String,
    pub question: Question,
    pub answers: Vec<Answer>,
    pub rule: Option<Rule>,
    pub status: ResultCode,
    pub elapsed: usize,
    pub timestamp: DateTime<Utc>,
    pub cached: bool,
}

#[derive(Serialize, Clone)]
pub enum Statistic {
    Count(usize),
    Average(Average),
    Request(Request),
    Requests(Vec<Request>),
    Cache(Cache),
}

#[derive(Default)]
pub struct Statistics {
    statistics: HashMap<&'static str, Statistic>,
}

impl Statistics {
    #[inline]
    pub async fn record(value: Statistic) {
        let mut statistics = STATISTICS.write().await;
        value.record(&mut statistics.statistics);
    }

    #[inline]
    pub async fn retrieve(
        statistic: &str,
        from: Option<String>,
        to: Option<String>,
    ) -> Option<Statistic> {
        let statistics = STATISTICS.read().await;

        match statistics.statistics.get(statistic) {
            Some(&Statistic::Requests(ref requests)) => {
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
    pub async fn statistics() -> HashMap<&'static str, Statistic> {
        let statistics = STATISTICS.read().await;
        statistics.statistics.clone()
    }
}
