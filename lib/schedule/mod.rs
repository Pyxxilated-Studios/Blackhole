use std::{
    num::NonZeroU64,
    sync::{Arc, LazyLock},
    time::Duration,
};

use chrono::{DateTime, Utc};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::sleep};

use crate::filter::Filter;

static SCHEDULER: LazyLock<Arc<RwLock<Scheduler>>> = LazyLock::new(Arc::default);

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, PartialOrd, Hash)]
pub enum Sched {
    Filters,
}

impl Sched {
    async fn run(&self) {
        match self {
            Sched::Filters => {
                Filter::reset().await;
                Filter::update().await;
            }
        }
    }

    async fn init(&self) {
        match self {
            Sched::Filters => {
                Filter::update().await;
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Schedule {
    name: Sched,
    schedule: NonZeroU64,
}

#[derive(Default)]
pub struct Scheduler {
    schedules: FxHashMap<Sched, (DateTime<Utc>, NonZeroU64)>,
}

impl Scheduler {
    async fn run() {
        loop {
            let mut soonest = Utc::now();

            let schedules = { SCHEDULER.read().await.schedules.clone() };

            for (schedule, (at, time)) in schedules {
                if at <= Utc::now() {
                    schedule.run().await;
                    Self::schedule(Schedule {
                        name: schedule,
                        schedule: time,
                    })
                    .await;
                } else if at < soonest {
                    soonest = at;
                }
            }

            sleep(
                (soonest.time() - Utc::now().time())
                    .to_std()
                    .unwrap_or_default(),
            )
            .await;
        }
    }

    async fn schedule(schedule: Schedule) {
        SCHEDULER
            .write()
            .await
            .schedules
            .entry(schedule.name)
            .and_modify(|(when, sched)| {
                *when = Utc::now()
                    + chrono::Duration::from_std(Duration::from_secs(schedule.schedule.into()))
                        .unwrap();
                *sched = schedule.schedule;
            })
            .or_insert_with(|| {
                (
                    Utc::now()
                        + chrono::Duration::from_std(Duration::from_secs(schedule.schedule.into()))
                            .unwrap(),
                    schedule.schedule,
                )
            });
    }

    pub async fn init(schedules: Vec<Schedule>) {
        for schedule in schedules {
            schedule.name.init().await;
            Self::schedule(schedule).await;
        }

        Self::run().await;
    }
}
