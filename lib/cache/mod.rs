use core::mem::size_of;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use hickory_proto::{rr::RecordType, xfer::DnsResponse};
use hickory_server::server::Request;
use lru_cache::LruCache;
use tokio::sync::RwLock;

use crate::statistics::{self, Statistic, Statistics};

type PacketExpires = (DnsResponse, Vec<Instant>);
type Entry = AHashMap<RecordType, PacketExpires>;

pub struct Cache {
    cache: LruCache<String, Entry>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            cache: LruCache::new(1024),
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
        let (ref response, expires) = {
            let mut cache = CACHE.write().await;
            cache
                .cache
                .get_mut(&request.query().original().name().to_string())
                .and_then(|entry| entry.get_mut(&request.query().query_type()))?
                .clone()
        };

        let mut resp = response.clone().into_message();

        let now = Instant::now();

        expires.iter().all(|expire| *expire >= now).then(|| {
            Statistics::record(Statistic::Cache(statistics::Cache {
                hits: 1,
                misses: 0,
                size: 0,
            }));

            resp.answers_mut()
                .iter_mut()
                .zip(expires)
                .for_each(|(answer, expire)| {
                    answer
                        .set_ttl(u32::try_from((expire - now).as_secs()).expect("Invalid expiry"));
                });

            response.clone()
        })
    }

    pub async fn insert(response: &DnsResponse) {
        let mut cache = CACHE.write().await;

        let key = response.queries()[0].name().to_string();
        let sub_key = response.queries()[0].query_type();

        let exists = cache
            .cache
            .get_mut(&key)
            .map(|inner| inner.contains_key(&sub_key));

        Statistics::record(Statistic::Cache(statistics::Cache {
            hits: 0,
            misses: 1,
            size: match exists {
                Some(true) => 0,
                Some(false) => size_of::<Entry>(),
                None => key.capacity() + size_of::<Entry>(),
            },
        }));

        let now = Instant::now();
        let value = response
            .answers()
            .iter()
            .map(|answer| now + Duration::from_secs(answer.ttl().into()))
            .collect();

        if let Some(entry) = cache.cache.get_mut(&key) {
            *entry.entry(sub_key).or_insert((response.clone(), value)) =
                (response.clone(), value.clone());
        } else {
            let mut entry = AHashMap::default();
            entry.insert(sub_key, (response.clone(), value));

            cache.cache.insert(key, entry);
        }
    }
}
