use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::BufRead,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use bstr::{BString, ByteSlice};
use chumsky::{prelude::*, text::newline};
use rayon::iter::{ParallelBridge, ParallelIterator};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

use crate::{
    config::{self, FilterList},
    dns,
};

static FILTER: LazyLock<Arc<RwLock<Filter>>> = LazyLock::new(Arc::default);

const DOMAIN_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_*";

#[derive(Debug, Clone, Serialize, PartialEq, PartialOrd)]
pub struct Rewrite {
    pub v4: IpAddr,
    pub v6: IpAddr,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, PartialOrd)]
pub(crate) struct Action {
    pub rewrite: Option<Rewrite>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, PartialOrd)]
pub enum Kind {
    Allow,
    Deny,
    #[default]
    None,
}

#[derive(Debug, Clone)]
pub enum Type {
    Host(IpAddr, String),
    Domain(String),
    Adblock(Kind, Box<Type>),
    Ip(IpAddr),
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, PartialOrd)]
pub struct Rule {
    pub(crate) domain: String,
    pub(crate) ty: Kind,
    pub(crate) action: Option<Action>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Rules {
    pub(crate) children: FxHashMap<BString, Rules>,
    pub(crate) rule: Option<Rule>,
}

#[derive(Default, Debug)]
pub struct Filter {
    pub(crate) lists: FxHashSet<FilterList>,
    pub(crate) rules: Rules,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    RequestError(#[from] reqwest::Error),
    #[error("{0}")]
    FilterError(String),
}

fn file_name_for(list: &FilterList) -> String {
    let mut hasher = DefaultHasher::new();
    list.hash(&mut hasher);
    format!("{}.txt", hasher.finish())
}

impl Filter {
    #[instrument(level = "info")]
    pub async fn update() {
        let filters = config::Config::get(|config| config.filters.clone()).await;

        let tasks = filters
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
            tokio::join!(task).0.unwrap();
        }
    }

    async fn download(filter: FilterList) -> Result<(), Error> {
        if !Path::new(&file_name_for(&filter)).exists() {
            info!("Fetching {}", filter.url);

            let client = reqwest::Client::builder()
                .brotli(true)
                .gzip(true)
                .build()
                .unwrap();

            let response = client.get(&filter.url).send().await?;

            if !response.status().is_success() {
                return Err(Error::from(response.error_for_status().expect_err("")));
            }

            let contents = response.text().await?;

            std::fs::write(file_name_for(&filter), contents)?;
        }

        Self::import(filter).await
    }

    fn lex() -> impl Parser<char, Vec<Type>, Error = Simple<char>> {
        let comment = one_of("#!")
            .then(take_until(newline().or(end())))
            .labelled("Comment")
            .padded();

        let part = one_of(DOMAIN_CHARS)
            .repeated()
            .at_least(1)
            .collect::<String>();
        let domain = part
            .clone()
            .separated_by(just('.'))
            .at_least(1)
            .map(|a| a.join("."));

        let domain = just('.')
            .or_not()
            .then(domain)
            .then(just('.').or_not())
            .labelled("Domain")
            .map(|((a, b), c)| {
                format!(
                    "{}{b}{}",
                    if a.is_some() { "." } else { "" },
                    if c.is_some() { "." } else { "" }
                )
            });

        let ip6_abbreviate = just("::").then(text::int::<_, Simple<char>>(16));
        let ipv6_ = text::int::<_, Simple<char>>(16)
            .then(just("::"))
            .then(text::int(16));
        let ipv6__ = text::int::<_, Simple<char>>(16)
            .separated_by(just(":").ignored())
            .at_most(8)
            .at_least(2)
            .then(text::int(16));

        let ipv6 = ip6_abbreviate
            .map(|(a, b)| String::from(a) + &b)
            .or(ipv6_.map(|((a, b), c)| a + b + &c))
            .or(ipv6__.map(|(a, b)| a.join(":") + &b))
            .then_ignore(just("%").then(part).or_not());

        let ipv4 = text::int::<_, Simple<char>>(10)
            .separated_by(just('.').ignored())
            .exactly(4)
            .labelled("IP")
            .map(|ip| ip.join("."));

        let ip = ipv6
            .or(ipv4)
            .then_ignore(filter::<char, _, _>(text::Character::is_whitespace))
            .map(|ip| IpAddr::from_str(&ip).unwrap());

        let hosts = ip
            .clone()
            .then(domain.clone())
            .labelled("Hosts Syntax")
            .map(|(a, b)| Type::Host(a, b));

        let adblock_ = ip
            .clone()
            .map(Type::Ip)
            .or(domain.clone().map(Type::Domain));

        let adblock = just("@@||")
            .or(just("||@@"))
            .or(just("||"))
            .then(adblock_)
            .labelled("AdBlock Syntax")
            .map(|(kind, ty)| {
                Type::Adblock(
                    if kind.chars().any(|c| c == '@') {
                        Kind::Deny
                    } else {
                        Kind::Allow
                    },
                    Box::new(ty),
                )
            });

        let filter = hosts
            .or(ip.map(Type::Ip))
            .or(domain.map(Type::Domain))
            .or(adblock)
            .recover_with(skip_then_retry_until([]).consume_end());

        filter
            .padded_by(comment.repeated())
            .padded_by(text::whitespace().or(text::newline()))
            .padded()
            .repeated()
    }

    ///
    /// Parse a filter list into a bunch of individual filters
    ///
    /// # Errors
    /// This will only fail if the lexer fails (i.e. the filter list is invalid)
    ///
    pub fn parse(file: &Path) -> Result<Vec<Type>, Error> {
        let file = std::fs::File::open(file)?;
        let reader = std::io::BufReader::new(file);

        reader
            .lines()
            .filter_map(Result::ok)
            .par_bridge()
            .try_fold(
                || Vec::with_capacity(1024),
                |mut entries, line| {
                    let (l, errors) = Self::lex().parse_recovery(line);

                    if errors.is_empty() {
                        if let Some(ents) = l {
                            entries.extend(ents);
                        }
                        Ok(entries)
                    } else {
                        Err(Error::FilterError(String::from("Invalid filter list")))
                    }
                },
            )
            .try_reduce(
                || Vec::with_capacity(1024),
                |mut entries, ents| {
                    entries.extend(ents);
                    Ok(entries)
                },
            )
    }

    fn add(&mut self, entry: Type) {
        let (addr, ty, domain) = match entry {
            Type::Host(ip, domain) => (Some(ip), Kind::Deny, domain),
            Type::Domain(domain) => (None, Kind::Deny, domain),
            Type::Adblock(kind, ty) => match *ty {
                Type::Domain(domain) => (None, kind, domain),
                Type::Ip(_) | Type::Host(_, _) | Type::Adblock(_, _) => return,
            },
            Type::Ip(_) => return,
        };

        let node = domain
            .split('.')
            .rev()
            .fold(&mut self.rules, |current_node, part| {
                current_node.children.entry(part.into()).or_default()
            });

        let mut rule = node.rule.clone().unwrap_or(Rule {
            domain,
            ty,
            action: None,
        });

        if let Some(ref mut action) = rule.action {
            if let Some(ref mut re) = action.rewrite {
                match addr {
                    None => (),
                    Some(addr @ IpAddr::V4(_)) => re.v4 = addr,
                    Some(addr @ IpAddr::V6(_)) => re.v6 = addr,
                }
            } else {
                match addr {
                    None => (),
                    Some(addr @ IpAddr::V4(_)) => {
                        action.rewrite = Some(Rewrite {
                            v4: addr,
                            v6: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        });
                    }
                    Some(addr @ IpAddr::V6(_)) => {
                        action.rewrite = Some(Rewrite {
                            v6: addr,
                            v4: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        });
                    }
                }
            }
        } else {
            match addr {
                None => (),
                Some(addr @ IpAddr::V4(_)) => {
                    rule.action = Some(Action {
                        rewrite: Some(Rewrite {
                            v4: addr,
                            v6: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        }),
                    });
                }
                Some(addr @ IpAddr::V6(_)) => {
                    rule.action = Some(Action {
                        rewrite: Some(Rewrite {
                            v6: addr,
                            v4: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        }),
                    });
                }
            }
        }

        node.rule = Some(rule);
    }

    #[inline]
    pub fn insert(&mut self, entries: Vec<Type>) {
        for entry in entries {
            self.add(entry);
        }
    }

    ///
    /// Load a list into the filter
    ///
    /// # Errors
    /// If it fails to open the list
    ///
    #[instrument(skip(list), err)]
    pub async fn import(mut list: FilterList) -> Result<(), Error> {
        info!("loading filter list: {}", list.name);

        let file = file_name_for(&list);

        let entries = Self::parse(Path::new(&file))?;

        info!("Loaded {} filter(s) for {}", entries.len(), list.name);

        list.entries = entries.len();

        let mut filter = FILTER.write().await;
        filter.insert(entries);
        filter.lists.insert(list);

        Ok(())
    }

    ///
    /// Reset the Global Filter to a blank slate. This is mostly useful
    /// when removing filters
    ///
    /// # Errors
    /// This should only error when a filter list fails to be imported
    ///
    pub async fn reset() -> Result<(), Error> {
        let lists = {
            let mut filter = FILTER.write().await;
            filter.rules = Rules::default();
            filter.lists.clone()
        };

        for list in lists {
            Self::import(list).await?;
        }

        Ok(())
    }

    pub fn filter(&self, packet: &dns::packet::Packet) -> Option<Rule> {
        packet.questions[0]
            .name
            .name()
            .split(|&c| c == b'.')
            .rev()
            .try_fold(&self.rules, |current_node, entry| {
                match current_node.children.get(entry.as_bstr()) {
                    Some(entry) => Ok(entry),
                    None => Err(current_node),
                }
            })
            .map_or_else(|err| err.rule.clone(), |rule| rule.rule.clone())
    }

    pub fn check(packet: &dns::packet::Packet) -> Option<Rule> {
        FILTER
            .try_read()
            .map(|filter| filter.filter(packet))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::Path,
    };

    use crate::dns::{
        header::Header, packet::Packet, qualified_name::QualifiedName, question::Question,
        QueryType, ResultCode,
    };

    use super::Filter;

    #[test]
    fn parsing() {
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
                name: QualifiedName("localhost".into()),
                qtype: QueryType::A,
            }],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        };

        let entries = Filter::parse(Path::new("benches/test.txt"));
        assert!(entries.is_ok());

        let entries = entries.unwrap();
        assert_eq!(entries.len(), 81560);
        filter.insert(entries);

        let rule = filter.filter(&packet);
        assert!(rule.is_some());

        let rule = rule.unwrap();
        assert!(rule.action.is_some());

        let action = rule.action.unwrap();
        assert!(action.rewrite.is_some());

        let rewrite = action.rewrite.unwrap();
        assert_eq!(rewrite.v4, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(rewrite.v6, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }
}
