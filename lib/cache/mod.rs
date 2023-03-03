use core::mem::size_of;
use std::sync::LazyLock;
use std::{hash::BuildHasherDefault, time::Duration, time::Instant};

use rustc_hash::FxHashMap;
use tokio::sync::RwLock;
use trust_dns_proto::{rr::RecordType, xfer::DnsResponse};
use trust_dns_server::server::Request;

use crate::statistics::{self, Statistic, Statistics};

type PacketExpires = (DnsResponse, Vec<Instant>);
type Entry = FxHashMap<RecordType, PacketExpires>;

pub struct Cache {
    cache: FxHashMap<String, Entry>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            cache: FxHashMap::with_capacity_and_hasher(1024, BuildHasherDefault::default()),
        }
    }
}

static CACHE: LazyLock<RwLock<Cache>> = LazyLock::new(RwLock::default);

impl Cache {
    ///
    /// Retrieve an entry from the cache, if it exists
    ///
    /// # Panics
    /// The only way this may panic is if one of the answer
    /// records does not have a TTL (e.g. [`OPT`])
    ///
    pub async fn get(request: &Request) -> Option<DnsResponse> {
        let cache = &*CACHE.read().await;

        let response = cache
            .cache
            .get(&request.query().original().name().to_string())
            .and_then(|entry| entry.get(&request.query().query_type()));

        let now = Instant::now();

        response
            .cloned()
            .map(|(mut response, expires)| {
                expires.iter().all(|expire| *expire >= now).then(|| {
                    Statistics::record(Statistic::Cache(statistics::Cache {
                        hits: 1,
                        misses: 0,
                        size: 0,
                    }));

                    response
                        .answers_mut()
                        .iter_mut()
                        .zip(expires.into_iter())
                        .for_each(|(answer, expire)| {
                            answer.set_ttl(
                                u32::try_from((expire - now).as_secs()).expect("Invalid expiry"),
                            );
                        });

                    response
                })
            })
            .unwrap_or_default()
    }

    pub async fn insert(response: &DnsResponse) {
        let mut cache = CACHE.write().await;

        let key = response.queries()[0].name().to_string();
        let sub_key = response.queries()[0].query_type();

        Statistics::record(Statistic::Cache(statistics::Cache {
            hits: 0,
            misses: 1,
            size: match cache
                .cache
                .get(&key)
                .map(|inner| inner.contains_key(&sub_key))
            {
                Some(true) => 0,
                Some(false) => size_of::<Entry>(),
                None => key.capacity() + size_of::<Entry>(),
            },
        }));

        let value: Vec<_> = response
            .answers()
            .iter()
            .map(|answer| Instant::now() + Duration::from_secs(answer.ttl().into()))
            .collect();

        *cache
            .cache
            .entry(key)
            .or_default()
            .entry(sub_key)
            .or_insert((response.clone(), value)) = (response.clone(), value.clone());
    }
}
