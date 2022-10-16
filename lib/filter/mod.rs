use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use chumsky::{prelude::*, text::newline};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

use crate::{
    config::{self, FilterList},
    dns,
};

pub type Span = std::ops::Range<usize>;

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
    pub(crate) children: HashMap<String, Rules>,
    pub(crate) rule: Option<Rule>,
}

#[derive(Default, Debug)]
pub struct Filter {
    pub(crate) lists: HashSet<FilterList>,
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

impl Filter {
    #[instrument(level = "info")]
    pub async fn update() {
        let filters = config::Config::get(|config| config.filters.clone()).await;

        for filter in filters {
            info!("Fetching {}", filter.url);
            if let Err(err) = Self::download(filter).await {
                error!("{err}");
            }
        }
    }

    async fn download(filter: FilterList) -> Result<(), Error> {
        let client = reqwest::Client::builder().brotli(true).build().unwrap();

        let response = client.get(&filter.url).send().await?;

        if !response.status().is_success() {
            return Err(Error::from(response.error_for_status().expect_err("")));
        }

        let contents = response.text().await?;

        let mut hasher = DefaultHasher::new();
        filter.hash(&mut hasher);
        let file = format!("{}.txt", hasher.finish());
        std::fs::write(file.clone(), contents)?;

        Self::import(filter).await
    }

    fn lex() -> impl Parser<char, Vec<Type>, Error = Simple<char>> {
        let comment = one_of("#!")
            .then(take_until(newline().or(end())))
            .labelled("Comment")
            .padded();

        let part = one_of(DOMAIN_CHARS).repeated().at_least(1);
        let domain = part.clone().separated_by(just('.')).at_least(1).map(|v| {
            v.iter()
                .map(|a| a.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(".")
        });

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
    pub fn parse(file: &Path) -> Result<Option<Vec<Type>>, Error> {
        let src = std::fs::read_to_string(file)?;

        let (entries, errors) = Self::lex().parse_recovery(src);

        if errors.is_empty() {
            Ok(entries)
        } else {
            println!("{errors:#?}");
            Err(Error::FilterError(String::from("Invalid filter list")))
        }
    }

    fn insert(&mut self, entry: Type) {
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
                current_node.children.entry(part.to_string()).or_default()
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

    ///
    /// Load a list into the filter
    ///
    /// # Errors
    /// If it fails to open the list
    ///
    #[instrument(skip(list), err)]
    pub async fn import(mut list: FilterList) -> Result<(), Error> {
        info!("loading filter list: {}", list.name);

        let mut hasher = DefaultHasher::new();
        list.hash(&mut hasher);
        let file = format!("{}.txt", hasher.finish());

        let entries = Self::parse(Path::new(&file))?.unwrap();

        info!("Loaded {} filter(s)", entries.len());

        list.entries = entries.len();

        let mut filter = FILTER.write().await;

        for entry in entries {
            filter.insert(entry);
        }

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

    pub fn check(packet: &dns::packet::Packet) -> Option<Rule> {
        FILTER
            .try_read()
            .map(|filter| {
                packet.questions[0]
                    .name
                    .name()
                    .split('.')
                    .rev()
                    .try_fold(&filter.rules, |current_node, entry| {
                        match current_node.children.get(entry) {
                            Some(entry) => Ok(entry),
                            None => Err(current_node),
                        }
                    })
                    .map_or_else(|err| err.rule.clone(), |rule| rule.rule.clone())
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{Filter, Kind, Rule, Rules};

    #[test]
    fn parsing() {
        let mut _filter = Filter::default();
    }
}
