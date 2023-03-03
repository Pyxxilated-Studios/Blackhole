use std::{
    sync::LazyLock,
    time::{Duration, Instant, SystemTime},
};

use futures::future::select_all;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::sleep};
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
    #[instrument]
    async fn run(&self) {
        match self {
            Sched::Filters => {
                Filter::reset().await;
            }
            Sched::Logs => {
                let cutoff = SystemTime::now()
                    - Config::get(|config| {
                        config
                            .schedules
                            .iter()
                            .find(|sched| sched.name == Sched::Logs)
                            .map(|sched| sched.schedule)
                    })
                    .await
                    .unwrap_or(Duration::from_secs(60 * 60 * 6));

                Statistics::modify(statistics::REQUESTS, |statistics| {
                    if let statistics::Statistic::Requests(requests) = statistics {
                        requests.retain(|request| match request.timestamp.duration_since(cutoff) {
                            Ok(diff) => diff.is_zero(),
                            Err(_) => true,
                        });
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

#[cfg_attr(any(debug_assertions, test), derive(PartialEq))]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Schedule {
    pub name: Sched,
    #[serde(with = "humantime_serde", default)]
    pub schedule: Duration,
}

#[derive(Clone)]
struct ScheduleInterval(Sched, Duration, Instant);

impl std::future::Future for ScheduleInterval {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self.2.duration_since(std::time::Instant::now()).is_zero() {
            std::task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }
}

#[derive(Default)]
pub struct Scheduler {
    schedules: FxHashMap<Sched, (Instant, Duration)>,
}

impl Scheduler {
    #[instrument]
    async fn run() {
        loop {
            let schedules = SCHEDULER.read().await.schedules.clone();

            if schedules.is_empty() {
                sleep(Duration::from_secs(5)).await;
                continue;
            }

            let intervals = schedules
                .into_iter()
                .map(|(sched, (at, time))| ScheduleInterval(sched, time, at))
                .collect::<Vec<_>>();
            let (_, idx, _) = select_all(intervals.clone()).await;

            let ScheduleInterval(schedule, next, _) = intervals[idx].clone();

            trace!("Running schedule: {schedule:?}");
            schedule.run().await;
            trace!("Schedule completed");

            Self::schedule(Schedule {
                name: schedule,
                schedule: next,
            })
            .await;
        }
    }

    async fn schedule(schedule: Schedule) -> Instant {
        trace!("Rescheduling {schedule:?}");

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
        for schedule in schedules {
            schedule.name.init().await;
            Self::schedule(schedule).await;
        }

        Self::run().await;
    }
}
