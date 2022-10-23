use core::mem::size_of;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

use crate::{
    dns::{
        packet::{Packet, DNS_PACKET_SIZE},
        QueryType,
    },
    statistics::{self, Statistic, Statistics},
};

type PacketExpires = (Packet, Vec<DateTime<Utc>>);

#[derive(Debug, Default)]
pub struct Cache {
    cache: HashMap<String, HashMap<QueryType, PacketExpires>>,
}

static CACHE: LazyLock<Arc<RwLock<Cache>>> = LazyLock::new(Arc::default);

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
            .get(&packet.questions[0].name.name())
            .and_then(|entry| entry.get(&packet.questions[0].qtype))
            .cloned();

        match response {
            Some((mut packet, expires)) => {
                if expires.iter().any(|expire| *expire <= Utc::now()) {
                    None
                } else {
                    Statistics::record(Statistic::Cache(statistics::Cache {
                        hits: 1,
                        misses: 0,
                        size: 0,
                    }))
                    .await;

                    packet.answers = packet
                        .answers
                        .into_iter()
                        .zip(expires.into_iter())
                        .map(|(mut answer, expire)| {
                            answer.record().unwrap().ttl =
                                ((expire - Utc::now()).num_seconds() as u32).into();
                            answer
                        })
                        .collect();

                    Some(packet)
                }
            }
            None => None,
        }
    }

    pub async fn insert(packet: Packet) {
        let mut cache = CACHE.write().await;

        let key = packet.questions[0].name.name().clone();

        Statistics::record(Statistic::Cache(statistics::Cache {
            hits: 0,
            misses: 1,
            size: size_of::<String>() * key.capacity()
                + size_of::<HashMap<QueryType, PacketExpires>>()
                + DNS_PACKET_SIZE,
        }))
        .await;

        *cache
            .cache
            .entry(key)
            .or_default()
            .entry(packet.questions[0].qtype)
            .or_default() = (
            packet.clone(),
            packet
                .answers
                .iter()
                .map(|answer| {
                    Utc::now()
                        + Duration::seconds(i64::from(u32::from(answer.ttl().unwrap_or_default())))
                })
                .collect(),
        );
    }
}
