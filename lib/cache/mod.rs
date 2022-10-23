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
        QueryType, Record,
    },
    statistics::{self, Statistic, Statistics},
};

#[derive(Debug, Default)]
pub struct Cache {
    cache: HashMap<String, HashMap<QueryType, (Packet, DateTime<Utc>)>>,
}

static CACHE: LazyLock<Arc<RwLock<Cache>>> = LazyLock::new(Arc::default);

impl Cache {
    pub async fn get(packet: &Packet) -> Option<Packet> {
        let cache = CACHE.read().await;

        let response = cache
            .cache
            .get(&packet.questions[0].name.name())
            .and_then(|entry| entry.get(&packet.questions[0].qtype))
            .cloned();

        match response {
            Some((packet, expires)) if expires >= Utc::now() => {
                Statistics::record(Statistic::Cache(statistics::Cache {
                    hits: 1,
                    misses: 0,
                    size: 0,
                }))
                .await;

                Some(packet)
            }
            _ => None,
        }
    }

    pub async fn insert(packet: Packet) {
        let mut cache = CACHE.write().await;

        let key = packet.questions[0].name.name().clone();
        let ttl = packet
            .answers
            .first()
            .and_then(Record::ttl)
            .unwrap_or_default();

        Statistics::record(Statistic::Cache(statistics::Cache {
            hits: 0,
            misses: 1,
            size: size_of::<String>() * key.capacity()
                + size_of::<HashMap<QueryType, (Packet, DateTime<Utc>)>>()
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
            Utc::now() + Duration::seconds(i64::from(u32::from(ttl))),
        );
    }
}
