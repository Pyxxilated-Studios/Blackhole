use std::sync::{LazyLock, RwLock};

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

pub static REGISTRY: LazyLock<RwLock<Registry>> = LazyLock::new(RwLock::default);

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Request {
    pub question: String,
    pub record: String,
}

pub static RULES_METRIC: LazyLock<Gauge> = LazyLock::new(Gauge::default);
pub static BLOCKED_METRIC: LazyLock<Counter> = LazyLock::new(Counter::default);
pub static REQUESTS_METRIC: LazyLock<Family<Request, Counter>> = LazyLock::new(Family::default);
pub static DURATION_METRIC: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        [0.1, 0.2, 0.5, 1.0, 10.0]
            .into_iter()
            // Convert to nanoseconds
            .map(|a| a * 1_000_000_000.0),
    )
});

pub fn init() {
    let mut registry = REGISTRY.write().expect("Unable to init registry");

    registry.register("requests", "Number of requests", REQUESTS_METRIC.clone());

    registry.register(
        "request_duration",
        "Duration of request",
        DURATION_METRIC.clone(),
    );

    registry.register(
        "blocked",
        "Number of requests blocked",
        BLOCKED_METRIC.clone(),
    );

    registry.register("rules", "Number of rules", RULES_METRIC.clone());
}
