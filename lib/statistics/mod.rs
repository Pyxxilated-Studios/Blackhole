use std::{collections::HashMap, sync::Arc};

use lazy_static::lazy_static;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;

lazy_static! {
    pub static ref STATISTICS: Arc<RwLock<Statistics>> = Arc::default();
}

pub const REQUEST: &str = "requests";
pub const AVERAGE_REQUEST_TIME: &str = "average";

pub trait Record {
    fn record(&self, entry: &'static str, stats: &mut HashMap<&'static str, Vec<Value>>);
}

impl<S> Record for S
where
    S: Serialize,
{
    #[inline]
    fn record(&self, entry: &'static str, stats: &mut HashMap<&'static str, Vec<Value>>) {
        stats.entry(entry).or_default().push(json!(self));
    }
}

#[derive(Default)]
struct Count {
    count: usize,
    average: usize,
    sum: usize,
}
#[derive(Default)]
pub struct Statistics {
    statistics: HashMap<&'static str, Vec<Value>>,
    counts: HashMap<&'static str, Count>,
}

impl Statistics {
    #[inline]
    pub fn record<R>(&mut self, entry: &'static str, value: &R) -> &mut Statistics
    where
        R: Record,
    {
        value.record(entry, &mut self.statistics);
        self
    }

    #[inline]
    pub fn count(&mut self, entry: &'static str, value: usize) -> &mut Statistics {
        let count = self.counts.entry(entry).or_default();
        count.count += 1;
        count.average = (count.average as i64
            + ((value as i64 - count.average as i64) / count.count as i64))
            as usize;
        count.sum += value;
        self
    }

    #[inline]
    pub fn requests(&self) -> Option<&Vec<Value>> {
        self.statistics.get(REQUEST)
    }

    #[inline]
    pub fn request_time(&self) -> usize {
        self.counts
            .get(AVERAGE_REQUEST_TIME)
            .map_or(0, |v| v.average)
    }
}
