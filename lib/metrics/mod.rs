use std::sync::{LazyLock, RwLock};

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

pub static REGISTRY: LazyLock<RwLock<Registry>> = LazyLock::new(RwLock::default);

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Request {
    pub client: String,
    pub question: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Cache {
    pub hit: String,
}

pub static CACHE: LazyLock<Family<Cache, Counter>> = LazyLock::new(Family::default);
pub static RULES: LazyLock<Gauge> = LazyLock::new(Gauge::default);
pub static BLOCKED: LazyLock<Counter> = LazyLock::new(Counter::default);
pub static REQUESTS: LazyLock<Family<Request, Counter>> = LazyLock::new(Family::default);
pub static DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        [0.1, 0.2, 0.5, 1.0, 10.0]
            .into_iter()
            // Convert to nanoseconds
            .map(|a| a * 1_000_000_000.0),
    )
});

pub fn init() {
    let mut registry = REGISTRY.write().expect("Unable to init registry");

    registry.register("blackhole_requests", "Number of requests", REQUESTS.clone());
    registry.register(
        "blackhole_request_duration",
        "Duration of requests",
        DURATION.clone(),
    );
    registry.register(
        "blackhole_requests_blocked",
        "Number of requests blocked",
        BLOCKED.clone(),
    );
    registry.register("blackhole_rules", "Number of rules", RULES.clone());
    registry.register("blackhole_cache", "Cache effectiveness", CACHE.clone());
}
