use std::{sync::LazyLock, time::Duration};

use chrono::{DateTime, Utc};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{watch::Receiver, RwLock},
    time::sleep,
};
use tracing::{instrument, trace};

use crate::{
    config::Config,
    filter::Filter,
    statistics::{self, Statistics},
};

static SCHEDULER: LazyLock<RwLock<Scheduler>> = LazyLock::new(RwLock::default);

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, PartialOrd, Hash)]
pub enum Sched {
    Filters,
    Logs,
}

impl Sched {
    async fn run(&self) {
        match self {
            Sched::Filters => {
                Filter::reset().await;
            }
            Sched::Logs => {
                let now = Utc::now()
                    - chrono::Duration::from_std(
                        Config::get(|config| {
                            config
                                .schedules
                                .iter()
                                .find(|sched| sched.name == Sched::Logs)
                                .map(|sched| sched.schedule)
                        })
                        .await
                        .unwrap_or(Duration::from_secs(60 * 60 * 6)),
                    )
                    .unwrap();

                Statistics::modify(statistics::REQUESTS, |statistics| {
                    if let statistics::Statistic::Requests(requests) = statistics {
                        requests.retain(|request| request.timestamp > now);
                    }
                });
            }
        }
    }

    async fn init(&self) {
        match self {
            Sched::Filters => {
                Filter::init().await;
            }
            Sched::Logs => {}
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Schedule {
    pub name: Sched,
    #[serde(with = "humantime_serde", default)]
    pub schedule: Duration,
}

#[derive(Default)]
pub struct Scheduler {
    schedules: FxHashMap<Sched, (DateTime<Utc>, Duration)>,
}

impl Scheduler {
    #[instrument(skip(shutdown_signal))]
    async fn run(mut shutdown_signal: Receiver<bool>) {
        loop {
            let mut soonest = Utc::now();

            let schedules = { SCHEDULER.read().await.schedules.clone() };

            for (schedule, (at, time)) in schedules {
                if at <= Utc::now() {
                    trace!("Running schedule: {schedule:?}");

                    schedule.run().await;

                    let next = Self::schedule(Schedule {
                        name: schedule,
                        schedule: time,
                    })
                    .await;

                    if next < soonest {
                        soonest = next;
                    }
                } else if at < soonest {
                    soonest = at;
                }
            }

            tokio::select! {
                _ =  sleep((soonest.time() - Utc::now().time()).to_std().unwrap_or_default()) => {}
                _ = shutdown_signal.changed() => {
                    break;
                }
            }
        }
    }

    #[instrument(skip(schedule))]
    async fn schedule(schedule: Schedule) -> DateTime<Utc> {
        trace!("Rescheduling {schedule:?}");

        SCHEDULER
            .write()
            .await
            .schedules
            .entry(schedule.name)
            .and_modify(|(when, sched)| {
                *when = Utc::now() + chrono::Duration::from_std(schedule.schedule).unwrap();
                *sched = schedule.schedule;
            })
            .or_insert_with(|| {
                (
                    Utc::now() + chrono::Duration::from_std(schedule.schedule).unwrap(),
                    schedule.schedule,
                )
            })
            .0
    }

    #[instrument(skip(shutdown_signal))]
    pub async fn init(shutdown_signal: Receiver<bool>, schedules: Vec<Schedule>) {
        for schedule in schedules {
            schedule.name.init().await;
            Self::schedule(schedule).await;
        }

        Self::run(shutdown_signal).await;
    }
}
