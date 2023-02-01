use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::LazyLock,
    time::SystemTime,
};

use bstr::ByteSlice;
use regex::Regex;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

use crate::{
    config::Config,
    dns::{
        packet::Packet, qualified_name::QualifiedName, question::Question, QueryType, Record,
        ResultCode, Ttl, RR,
    },
    schedule::Sched,
    server::handler::Handler,
};

use self::rules::{Kind, Rule, Rules};

pub mod rules;

static FILTER: LazyLock<RwLock<Filter>> = LazyLock::new(RwLock::default);
static REPLACEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("\\\\*").expect("Failed to parse regex"));

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct List {
    pub name: String,
    pub url: String,
    #[serde(skip)]
    pub entries: usize,
}

impl ToString for List {
    fn to_string(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{}.txt", hasher.finish())
    }
}

impl PartialEq for List {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.url == other.url
    }
}

impl Hash for List {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.url.hash(state);
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Default)]
pub struct Filter {
    pub lists: FxHashSet<List>,
    pub rules: Rules,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    RequestError(Box<ureq::Error>),
    #[error("{0}")]
    DownloadError(String),
    #[error("{0}")]
    FilterError(String),
}

impl From<ureq::Error> for Error {
    fn from(value: ureq::Error) -> Self {
        Error::RequestError(Box::new(value))
    }
}

impl Filter {
    pub async fn init() {
        Self::update().await;
        if let Err(err) = Self::import().await {
            error!("{err:#?}");
        }
    }

    #[instrument(level = "info")]
    pub async fn update() {
        let tasks = Config::get(|config| config.filters.clone())
            .await
            .into_iter()
            .map(|filter| {
                tokio::spawn(async move {
                    if let Err(err) = Self::download(filter).await {
                        error!("{err}");
                    }
                })
            })
            .collect::<Vec<_>>();

        for task in tasks {
            let _ = tokio::join!(task).0;
        }
    }

    async fn download(list: List) -> Result<(), Error> {
        let path = list.to_string();
        let path = Path::new(&path);

        let schedule = Config::get(|config| {
            config
                .schedules
                .iter()
                .find(|sched| sched.name == Sched::Filters)
                .map(|sched| sched.schedule)
        })
        .await
        .unwrap_or(std::time::Duration::ZERO);

        let is_past_due = if path.exists() {
            SystemTime::now()
                .duration_since(path.metadata()?.modified()?)
                .unwrap_or_default()
                >= schedule
        } else {
            true
        };

        if is_past_due {
            info!("Fetching {}", list.url);

            let response = ureq::get(&list.url).call()?;

            if response.status() != 200 {
                return Err(Error::DownloadError(format!(
                    "{}: {}",
                    response.status(),
                    response.into_string()?
                )));
            };

            let mut len = response
                .header("Content-Length")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap();

            let mut response = response.into_reader();
            let mut writer = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(list.to_string())?;

            while len > 0 {
                let mut bytes = [0; 8192];
                let length = response.read(&mut bytes).unwrap_or_default();

                writer.write_all(&bytes[..length]).unwrap();

                len -= length;
            }
        }

        let mut filter = FILTER.write().await;
        filter.lists.insert(list);

        Ok(())
    }

    ///
    /// Load a list into the filter
    ///
    /// # Errors
    /// If it fails to open the list
    ///
    #[instrument]
    pub async fn import() -> Result<(), Error> {
        let rules = {
            let filter = FILTER.read().await;

            filter
                .lists
                .iter()
                .cloned()
                .try_fold(Rules::default(), |mut rules, mut list| {
                    info!("loading filter list: {}", list.name);

                    rules.merge(Rules::try_from(&mut list)?);

                    info!("Loaded {} filter(s) for {}", list.entries, list.name);

                    Ok::<Rules, Error>(rules)
                })?
        };

        let mut filter = FILTER.write().await;
        filter.rules = rules;

        Ok(())
    }

    ///
    /// Reset the Global Filter to a blank slate. This is mostly useful
    /// when removing filters
    ///
    pub async fn reset() {
        FILTER.read().await.lists.iter().for_each(|list| {
            std::fs::remove_file(list.to_string()).unwrap_or_default();
        });

        Self::update().await;
        if let Err(err) = Self::import().await {
            error!("{err:#?}");
        }
    }

    #[inline]
    pub fn filter(&self, packet: &Packet) -> Option<Rule> {
        packet.questions[0]
            .name
            .name()
            .split(|&c| c == b'.')
            .rev()
            .try_fold(&self.rules, |current_node, entry| {
                if let Some(entry) = current_node.children.get(entry.as_bstr()) {
                    Ok(entry)
                } else {
                    match current_node.children.iter().find(|(key, _)| {
                        if !key.contains(&b'*') {
                            return false;
                        }

                        let key = String::from_utf8_lossy(key.as_slice());
                        let re = REPLACEMENT.replace_all(&key, ".*");
                        let matcher = Regex::new(&re).expect("Failed to parse rule regex");
                        matcher.is_match(&String::from_utf8_lossy(entry))
                    }) {
                        Some((_, entry)) => Ok(entry),
                        None => Err(current_node),
                    }
                }
            })
            .map_or_else(|err| &err.rule, |rule| &rule.rule)
            .clone()
    }

    pub fn check(packet: &Packet) -> Option<Rule> {
        FILTER
            .try_read()
            .map(|filter| filter.filter(packet))
            .unwrap_or_default()
    }

    pub(crate) fn apply<Buff>(handler: &mut Handler<Buff>, packet: &mut Packet) {
        match Filter::check(packet) {
            Some(rule) if rule.ty == Kind::Deny => {
                let action = rule.action.clone();
                handler.rule = Some(rule);
                let mut packet = packet;
                packet.header.recursion_available = true;
                packet.header.response = true;
                packet.header.rescode = ResultCode::NOERROR;
                packet.header.truncated_message = false;
                match packet.questions.first() {
                    Some(Question {
                        qtype: QueryType::A,
                        ..
                    }) => {
                        packet.header.answers = 1;
                        packet.answers = vec![Record::A {
                            record: RR {
                                domain: QualifiedName(packet.questions[0].name.name().clone()),
                                ttl: Ttl(600),
                                query_type: QueryType::A,
                                class: 1,
                                data_length: 0,
                            },
                            addr: match action
                                .and_then(|action| action.rewrite)
                                .unwrap_or_default()
                                .v4
                            {
                                IpAddr::V4(addr) => addr,
                                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                            },
                        }];
                    }
                    Some(Question {
                        qtype: QueryType::AAAA,
                        ..
                    }) => {
                        packet.header.answers = 1;
                        packet.answers = vec![Record::AAAA {
                            record: RR {
                                domain: QualifiedName(packet.questions[0].name.name().clone()),
                                ttl: Ttl(600),
                                query_type: QueryType::AAAA,
                                class: 1,
                                data_length: 0,
                            },
                            addr: match action
                                .and_then(|action| action.rewrite)
                                .unwrap_or_default()
                                .v6
                            {
                                IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
                                IpAddr::V6(addr) => addr,
                            },
                        }];
                    }
                    _ => {}
                }
                packet.authorities = Vec::default();
                packet.resources = Vec::default();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pretty_assertions::assert_eq;

    use crate::{
        dns::{
            header::Header, packet::Packet, qualified_name::QualifiedName, question::Question,
            QueryType, ResultCode,
        },
        filter::rules::{Kind, Rules},
    };

    use super::Filter;

    #[test]
    fn parsing() {
        let mut filter = Filter::default();

        let entries = Rules::parse(Path::new("benches/test.txt"));
        assert!(entries.is_ok());

        let entries = entries.unwrap();
        assert_eq!(filter.rules.insert(entries), 81561);
    }

    #[test]
    fn checking() {
        let mut filter = Filter::default();

        let packet = Packet {
            header: Header {
                id: 0,
                recursion_desired: true,
                truncated_message: false,
                authoritative_answer: false,
                opcode: 0,
                response: true,
                rescode: ResultCode::NOERROR,
                checking_disabled: false,
                authed_data: true,
                z: false,
                recursion_available: true,
                questions: 1,
                answers: 0,
                authoritative_entries: 0,
                resource_entries: 0,
            },
            questions: vec![Question {
                name: QualifiedName("zz3r0.com".into()),
                qtype: QueryType::A,
                class: 1u16,
            }],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        };

        let entries = Rules::parse(Path::new("benches/test.txt")).unwrap();
        filter.rules.insert(entries);

        let rule = filter.filter(&packet);
        assert!(rule.is_some());

        let rule = rule.unwrap();
        assert_eq!(rule.ty, Kind::Deny);
    }

    #[test]
    fn regex_matching() {
        let mut filter = Filter::default();

        let packet = Packet {
            header: Header {
                id: 0,
                recursion_desired: true,
                truncated_message: false,
                authoritative_answer: false,
                opcode: 0,
                response: true,
                rescode: ResultCode::NOERROR,
                checking_disabled: false,
                authed_data: true,
                z: false,
                recursion_available: true,
                questions: 1,
                answers: 0,
                authoritative_entries: 0,
                resource_entries: 0,
            },
            questions: vec![Question {
                name: QualifiedName("gmail.com".into()),
                qtype: QueryType::A,
                class: 1u16,
            }],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        };

        let entries = Rules::parse(Path::new("benches/test.txt")).unwrap();
        filter.rules.insert(entries);

        let rule = filter.filter(&packet);
        assert!(rule.is_some());

        let rule = rule.unwrap();
        assert_eq!(rule.ty, Kind::Deny);
        assert_eq!(rule.domain, "*mail.com");
    }
}
