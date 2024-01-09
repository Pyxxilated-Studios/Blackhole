use std::{
    sync::LazyLock,
    time::{Duration, Instant, SystemTime},
};

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::sleep};
use tracing::{debug, instrument};

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
    #[instrument]
    async fn run(&self) {
        match self {
            Self::Filters => {
                Filter::reset(None).await;
            }
            Self::Logs => {
                let schedule = Config::get(|config| {
                    config
                        .schedules
                        .iter()
                        .find(|sched| sched.name == Self::Logs)
                        .map(|sched| sched.schedule)
                })
                .await
                .unwrap_or(Duration::from_secs(60 * 60 * 6));

                let cutoff = SystemTime::now() - schedule;

                Statistics::modify(statistics::REQUESTS, |statistics| {
                    if let statistics::Statistic::Requests(requests) = statistics {
                        requests.retain(|request| {
                            request
                                .timestamp
                                .duration_since(cutoff)
                                .map_or(true, |diff| diff.is_zero())
                        });
                    }
                });
            }
        }
    }

    #[inline]
    async fn init(&self) {
        debug!("Running Sched init");
        match self {
            Self::Filters => {
                Filter::init().await;
            }
            Self::Logs => {}
        }
    }
}

#[cfg_attr(any(debug_assertions, test), derive(PartialEq, Eq))]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Schedule {
    pub name: Sched,
    #[serde(with = "humantime_serde", default)]
    pub schedule: Duration,
}

#[derive(Default)]
pub struct Scheduler {
    schedules: AHashMap<Sched, (Instant, Duration)>,
}

impl Scheduler {
    #[instrument]
    async fn run() {
        loop {
            let mut soonest = Instant::now();

            let schedules = { SCHEDULER.read().await.schedules.clone() };

            for (schedule, (at, time)) in schedules {
                if at <= Instant::now() {
                    debug!("Running schedule: {schedule:?}");
                    schedule.run().await;
                    debug!("Schedule completed");

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

            sleep(soonest - Instant::now()).await;
        }
    }

    async fn schedule(schedule: Schedule) -> Instant {
        debug!("Rescheduling {schedule:?}");

        SCHEDULER
            .write()
            .await
            .schedules
            .entry(schedule.name)
            .and_modify(|(when, sched)| {
                *when = Instant::now().checked_add(*sched).unwrap();
                *sched = schedule.schedule;
            })
            .or_insert_with(|| {
                (
                    Instant::now().checked_add(schedule.schedule).unwrap(),
                    schedule.schedule,
                )
            })
            .0
    }

    pub async fn init(schedules: Vec<Schedule>) {
        debug!("Running init for Schedules");
        for schedule in schedules {
            schedule.name.init().await;
            Self::schedule(schedule).await;
        }

        Self::run().await;
    }
}
