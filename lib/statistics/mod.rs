use std::{fmt::Debug, sync::Arc};

use chrono::prelude::*;
use lazy_static::lazy_static;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::dns::{question::Question, Record, ResultCode};

lazy_static! {
    pub static ref STATS: Arc<RwLock<Statistics>> = Arc::default();
}

#[derive(Debug, Serialize)]
pub struct Statistic {
    pub client: String,
    pub question: Question,
    pub answers: Vec<Record>,
    pub status: ResultCode,
    pub elapsed: usize,
    pub timestamp: DateTime<Utc>,
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

    pub fn requests(&self) -> &Vec<Statistic> {
        &self.statistics
    }
}
