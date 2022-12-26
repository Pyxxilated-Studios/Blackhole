use std::{
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
};

use bstr::BString;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{line_ending, not_line_ending, one_of, space0, space1},
    combinator::{eof, map, opt, peek},
    error::{context, ContextError, ParseError, VerboseError},
    multi::{count, many_m_n, many_till, separated_list1},
    sequence::{terminated, tuple},
    AsChar, IResult,
};
use rayon::{iter::ParallelIterator, prelude::ParallelBridge};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use super::Error;

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Serialize, PartialEq, PartialOrd, Deserialize)]
pub struct Rewrite {
    pub v4: IpAddr,
    pub v6: IpAddr,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, Serialize, PartialEq, PartialOrd, Deserialize)]
pub(crate) struct Action {
    pub rewrite: Option<Rewrite>,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, Serialize, PartialEq, PartialOrd, Deserialize)]
pub enum Kind {
    Allow,
    Deny,
    #[default]
    None,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone)]
pub enum Type {
    Host(IpAddr, String),
    Domain(String),
    Adblock(Kind, Box<Type>),
    Ip(IpAddr),
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, Serialize, PartialEq, PartialOrd, Deserialize)]
pub struct Rule {
    pub(crate) domain: String,
    pub(crate) ty: Kind,
    pub(crate) action: Option<Action>,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Default, Clone, PartialEq)]
pub struct Rules {
    pub(crate) children: FxHashMap<BString, Rules>,
    pub(crate) rule: Option<Rule>,
}

impl Rules {
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
                |mut entries, line| match Self::lex::<VerboseError<&str>>(&line) {
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

        match &mut domain
            .split('.')
            .rev()
            .fold(self, |current_node, part| {
                current_node.children.entry(part.into()).or_default()
            })
            .rule
        {
            Some(rule) => {
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
            r => {
                *r = Some(Rule {
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
                });
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

    pub fn merge(&mut self, rules: Rules) {
        for (child, rules) in rules.children {
            let new = self.children.entry(child).or_default();
            new.rule = rules.rule.clone();
            new.merge(rules);
        }
    }
}

impl TryFrom<&mut super::List> for Rules {
    type Error = super::Error;

    fn try_from(value: &mut super::List) -> Result<Self, Self::Error> {
        let mut rules = Self::default();
        let entries = Rules::parse(Path::new(&value.to_string()))?;
        value.entries = rules.insert(entries);

        Ok(rules)
    }
}

const DOMAIN_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_*";

fn ip4_num<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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

fn ipv4<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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

fn ip6_num<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Vec<char>, E> {
    context("IP6_Num", many_m_n(1, 4, one_of("0123456789abcdefABCDEF")))(i)
}

fn ipv6<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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

fn ip<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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

fn domain<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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

fn hosts<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Type, E> {
    context(
        "Hosts",
        map(tuple((ip, space1, domain)), |(ip, _, domain)| {
            Type::Host(ip, domain)
        }),
    )(i)
}

fn adblock<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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

fn comment<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, &'a str, E> {
    context(
        "Comment",
        map(tuple((one_of("#!"), not_line_ending)), |(_, comment)| {
            comment
        }),
    )(i)
}

fn eol<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
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
