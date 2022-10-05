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

pub static STATISTICS: LazyLock<Arc<RwLock<Statistics>>> = LazyLock::new(Arc::default);

pub const REQUEST: &str = "requests";
pub const AVERAGE_REQUEST_TIME: &str = "average";

impl Statistic {
    fn record(self, stats: &mut HashMap<&'static str, Statistic>) {
        match self {
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
pub struct Request {
    pub client: String,
    pub question: Question,
    pub answers: Vec<Answer>,
    pub rule: Option<Rule>,
    pub status: ResultCode,
    pub elapsed: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Serialize, Clone)]
pub enum Statistic {
    Count(usize),
    Average(Average),
    Request(Request),
    Requests(Vec<Request>),
}

#[derive(Default)]
pub struct Statistics {
    statistics: HashMap<&'static str, Statistic>,
}

impl Statistics {
    #[inline]
    pub fn record(&mut self, value: Statistic) -> &mut Statistics {
        value.record(&mut self.statistics);
        self
    }

    #[inline]
    pub fn retrieve(&self, statistic: &str) -> Option<&Statistic> {
        self.statistics.get(statistic)
    }

    #[inline]
    pub fn statistics(&self) -> &HashMap<&'static str, Statistic> {
        &self.statistics
    }
}
