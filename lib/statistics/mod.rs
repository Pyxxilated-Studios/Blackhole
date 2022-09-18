use std::{fmt::Debug, sync::Arc};

use chrono::prelude::*;
use lazy_static::lazy_static;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::{
    dns::{question::Question, Record, ResultCode},
    filter::Rule,
};

lazy_static! {
    pub static ref STATISTICS: Arc<RwLock<Statistics>> = Arc::default();
}

#[derive(Debug, Serialize, Clone)]
pub struct Request {
    pub client: String,
    pub question: Question,
    pub answers: Vec<Record>,
    pub rule: Option<Rule>,
    pub status: ResultCode,
    pub elapsed: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub enum Statistic {
    Request(Request),
    Value(usize),
}

#[derive(Default)]
pub struct Statistics {
    statistics: Vec<Statistic>,
}

impl Statistics {
    pub fn record<S>(&mut self, stat: S)
    where
        Statistic: From<S>,
    {
        self.statistics.push(stat.into());
    }

    pub fn requests(&self) -> Vec<Request> {
        self.statistics
            .iter()
            .filter_map(|stat| {
                if let Statistic::Request(req) = stat {
                    Some(req.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}
