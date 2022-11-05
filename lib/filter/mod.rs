use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    sync::LazyLock,
};

use bstr::{BString, ByteSlice};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{line_ending, not_line_ending, one_of, space0, space1},
    combinator::{eof, map, opt, peek},
    error::{context, ContextError, ParseError},
    multi::{count, many_m_n, many_till, separated_list1},
    sequence::{terminated, tuple},
    AsChar, IResult,
};
use rayon::iter::{ParallelBridge, ParallelIterator};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

use crate::{config, dns};

static FILTER: LazyLock<RwLock<Filter>> = LazyLock::new(RwLock::default);

const DOMAIN_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_*";

#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct List {
    pub name: String,
    pub url: String,
    #[serde(skip)]
    pub entries: usize,
}

impl PartialEq for List {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.url == other.url
    }
}

impl std::hash::Hash for List {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.url.hash(state);
    }
}

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
    pub(crate) lists: FxHashSet<List>,
    pub(crate) rules: Rules,
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

fn file_name_for(list: &List) -> String {
    let mut hasher = DefaultHasher::new();
    list.hash(&mut hasher);
    format!("{}.txt", hasher.finish())
}

fn ip4_num<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, String, E> {
    context(
        "IP4_Num",
        alt((
            map(
                tuple((tag("1"), one_of("0123456789"), one_of("0123456789"))),
                |(a, b, c)| format!("{a}{b}{c}"),
            ),
            map(
                tuple((
                    tag("2"),
                    alt((
                        map(tuple((tag("5"), one_of("012345"))), |(a, b)| {
                            format!("{a}{b}")
                        }),
                        map(tuple((one_of("01234"), one_of("0123456789"))), |(a, b)| {
                            format!("{a}{b}")
                        }),
                    )),
                )),
                |(_, b)| format!("2{b}"),
            ),
            map(
                tuple((one_of("123456789"), one_of("0123456789"))),
                |(a, b)| format!("{a}{b}"),
            ),
            map(one_of("0123456789"), |a| format!("{a}")),
        )),
    )(i)
}

fn ipv4<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, IpAddr, E> {
    context(
        "IPV4",
        map(
            tuple((count(terminated(ip4_num, tag(".")), 3), ip4_num)),
            |(a, b)| IpAddr::from_str(&format!("{}.{b}", a.join("."))).unwrap(),
        ),
    )(i)
}

fn ip6_num<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Vec<char>, E> {
    context("IP6_Num", many_m_n(1, 4, one_of("0123456789abcdefABCDEF")))(i)
}

fn ipv6<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, IpAddr, E> {
    context(
        "IPV6",
        map(
            tuple((
                alt((
                    map(tuple((opt(ip6_num), tag("::"))), |(a, b)| {
                        format!("{}{b}", a.into_iter().flatten().collect::<String>())
                    }),
                    map(count(terminated(ip6_num, tag(":")), 7), |parts| {
                        parts
                            .into_iter()
                            .map(|v| v.into_iter().collect::<String>())
                            .reduce(|mut acc, e| {
                                acc.push(':');
                                acc.push_str(&e);
                                acc
                            })
                            .unwrap()
                    }),
                )),
                ip6_num,
                opt(tuple((tag("%"), take_while(AsChar::is_alphanum)))),
            )),
            |(a, b, _)| {
                IpAddr::from_str(&format!("{a}{}", b.into_iter().collect::<String>())).unwrap()
            },
        ),
    )(i)
}

fn ip<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, IpAddr, E> {
    context(
        "IP",
        map(
            tuple((alt((ipv4, ipv6)), peek(alt((space1, eol, eof))))),
            |(ip, _)| ip,
        ),
    )(i)
}

fn domain<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, String, E> {
    context(
        "Domain",
        map(
            separated_list1(
                tag("."),
                take_while1(|c| DOMAIN_CHARS.chars().any(|a| a == c)),
            ),
            |parts| parts.join("."),
        ),
    )(i)
}

fn hosts<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Type, E> {
    context(
        "Hosts",
        map(tuple((ip, space1, domain)), |(ip, _, domain)| {
            Type::Host(ip, domain)
        }),
    )(i)
}

fn adblock<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Type, E> {
    context(
        "Adblock",
        map(
            tuple((
                alt((tag("||@@"), tag("@@||"), tag("||"))),
                alt((map(ip, Type::Ip), map(domain, Type::Domain))),
            )),
            |(pre, ty)| {
                Type::Adblock(
                    if pre.chars().any(|c| c == '@') {
                        Kind::Allow
                    } else {
                        Kind::Deny
                    },
                    Box::new(ty),
                )
            },
        ),
    )(i)
}

fn comment<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, &'a str, E> {
    context(
        "Comment",
        map(tuple((one_of("#!"), not_line_ending)), |(_, comment)| {
            comment
        }),
    )(i)
}

fn eol<'a, E: ParseError<&'a str> + nom::error::ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, &str, E> {
    context(
        "EOL",
        map(
            tuple((space0, opt(comment), alt((eof, line_ending)))),
            |(_, _, _)| "",
        ),
    )(i)
}

impl Filter {
    #[instrument(level = "info")]
    pub async fn update() {
        let tasks = config::Config::get(|config| config.filters.clone())
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
            tokio::join!(task).0.unwrap();
        }
    }

    async fn download(filter: List) -> Result<(), Error> {
        if !Path::new(&file_name_for(&filter)).exists() {
            info!("Fetching {}", filter.url);

            let response = ureq::get(&filter.url).call()?;

            if response.status() != 200 {
                return Err(Error::DownloadError(format!(
                    "{}: {}",
                    response.status(),
                    response.into_string()?
                )));
            }

            let contents = response.into_string()?;

            std::fs::write(file_name_for(&filter), contents)?;
        }

        Self::import(filter).await
    }

    fn lex<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
        i: &'a str,
    ) -> IResult<&'a str, impl Iterator<Item = Option<Type>> + 'a, E> {
        context(
            "Lex",
            map(
                many_till(
                    tuple((
                        space0,
                        opt(alt((
                            hosts,
                            map(ip, Type::Ip),
                            map(domain, Type::Domain),
                            adblock,
                        ))),
                        eol,
                    )),
                    eof,
                ),
                |(a, _)| a.into_iter().map(|(_, b, _)| b),
            ),
        )(i)
    }

    ///
    /// Parse a filter list into a bunch of individual filters
    ///
    /// # Errors
    /// This will only fail if the lexer fails (i.e. the filter list is invalid)
    ///
    pub fn parse(file: &Path) -> Result<Vec<Type>, Error> {
        let file = std::fs::File::open(file)?;
        let reader = BufReader::new(file);

        reader
            .lines()
            .filter_map(Result::ok)
            .par_bridge()
            .try_fold(
                || Vec::with_capacity(1024),
                |mut entries, line| match Self::lex::<()>(&line) {
                    Err(_) => Err(Error::FilterError(String::from("Invalid filter list"))),
                    Ok((_, ents)) => {
                        entries.extend(ents.flatten());
                        Ok(entries)
                    }
                },
            )
            .try_reduce(
                || Vec::with_capacity(1024),
                |mut entries, entry| {
                    entries.extend(entry);
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

        let mut inserted = false;

        let rule = domain
            .split('.')
            .rev()
            .fold(&mut self.rules, |current_node, part| {
                current_node.children.entry(part.into()).or_default()
            })
            .rule
            .get_or_insert_with(|| {
                inserted = true;
                Rule {
                    domain,
                    ty,
                    action: match addr {
                        None => None,
                        Some(addr @ IpAddr::V4(_)) => Some(Action {
                            rewrite: Some(Rewrite {
                                v4: addr,
                                v6: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                            }),
                        }),
                        Some(addr @ IpAddr::V6(_)) => Some(Action {
                            rewrite: Some(Rewrite {
                                v6: addr,
                                v4: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            }),
                        }),
                    },
                }
            });

        if inserted {
            return;
        }

        if let Some(ref mut action) = rule.action {
            if let Some(ref mut rewrite) = action.rewrite {
                match addr {
                    None => (),
                    Some(addr @ IpAddr::V4(_)) => rewrite.v4 = addr,
                    Some(addr @ IpAddr::V6(_)) => rewrite.v6 = addr,
                }
            }
        }
    }

    #[inline]
    pub fn insert(&mut self, entries: Vec<Type>) -> usize {
        entries.into_iter().fold(0, |acc, entry| {
            self.add(entry);
            acc + 1
        })
    }

    ///
    /// Load a list into the filter
    ///
    /// # Errors
    /// If it fails to open the list
    ///
    #[instrument(skip(list), err)]
    pub async fn import(mut list: List) -> Result<(), Error> {
        info!("loading filter list: {}", list.name);

        let file = file_name_for(&list);

        let entries = Self::parse(Path::new(&file))?;

        let mut filter = FILTER.write().await;
        list.entries = filter.insert(entries);
        info!("Loaded {} filter(s) for {}", list.entries, list.name);
        filter.lists.insert(list);

        Ok(())
    }

    ///
    /// Reset the Global Filter to a blank slate. This is mostly useful
    /// when removing filters
    ///
    pub async fn reset() {
        let lists = {
            let mut filter = FILTER.write().await;
            filter.rules = Rules::default();
            filter.lists.clone()
        };

        for list in lists {
            std::fs::remove_file(file_name_for(&list)).unwrap_or_default();
        }
    }

    #[inline]
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
            .map_or_else(|err| &err.rule, |rule| &rule.rule)
            .clone()
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
    use std::path::Path;

    use crate::{
        dns::{
            header::Header, packet::Packet, qualified_name::QualifiedName, question::Question,
            QueryType, ResultCode,
        },
        filter::Kind,
    };

    use super::Filter;

    #[test]
    fn parsing() {
        let mut filter = Filter::default();

        let entries = Filter::parse(Path::new("benches/test.txt"));
        assert!(entries.is_ok());

        let entries = entries.unwrap();
        assert_eq!(filter.insert(entries), 81560);
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
            }],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        };

        let entries = Filter::parse(Path::new("benches/test.txt")).unwrap();
        filter.insert(entries);

        let rule = filter.filter(&packet);
        assert!(rule.is_some());

        let rule = rule.unwrap();
        assert_eq!(rule.ty, Kind::Deny);
    }
}
