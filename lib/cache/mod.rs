use core::mem::size_of;
use std::hash::BuildHasherDefault;
use std::sync::LazyLock;

use bstr::BString;
use chrono::{DateTime, Duration, Utc};
use rustc_hash::FxHashMap;
use tokio::sync::RwLock;

use crate::{
    dns::{
        packet::{Packet, DNS_PACKET_SIZE},
        QueryType,
    },
    statistics::{self, Statistic, Statistics},
};

type PacketExpires = (Packet, Vec<DateTime<Utc>>);
type Entry = FxHashMap<QueryType, PacketExpires>;

pub struct Cache {
    cache: FxHashMap<BString, Entry>,
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
    pub async fn get(packet: &Packet) -> Option<Packet> {
        let cache = CACHE.read().await;

        let response = cache
            .cache
            .get(packet.questions[0].name.name())
            .and_then(|entry| entry.get(&packet.questions[0].qtype));

        match response.cloned() {
            Some((mut packet, expires)) => {
                if expires.iter().any(|expire| *expire < Utc::now()) {
                    None
                } else {
                    Statistics::record(Statistic::Cache(statistics::Cache {
                        hits: 1,
                        misses: 0,
                        size: 0,
                    }));

                    packet.answers.iter_mut().zip(expires.into_iter()).for_each(
                        |(answer, expire)| {
                            answer.record().unwrap().ttl =
                                u32::try_from((expire - Utc::now()).num_seconds())
                                    .expect("Invalid expiry")
                                    .into();
                        },
                    );

                    Some(packet)
                }
            }
            None => None,
        }
    }

    pub async fn insert(packet: &Packet) {
        let mut cache = CACHE.write().await;

        let key = packet.questions[0].name.name().clone();
        let sub_key = packet.questions[0].qtype;

        Statistics::record(Statistic::Cache(statistics::Cache {
            hits: 0,
            misses: 1,
            size: match cache
                .cache
                .get(&key)
                .map(|inner| inner.contains_key(&sub_key))
            {
                Some(true) => 0,
                Some(false) => size_of::<Entry>() + DNS_PACKET_SIZE,
                None => key.capacity() + size_of::<Entry>() + DNS_PACKET_SIZE,
            },
        }));

        let value = packet
            .answers
            .iter()
            .map(|answer| {
                Utc::now()
                    + Duration::seconds(i64::from(u32::from(answer.ttl().unwrap_or_default())))
            })
            .collect();

        *cache
            .cache
            .entry(key)
            .or_default()
            .entry(sub_key)
            .or_default() = (packet.clone(), value);
    }
}
