use std::{
    borrow::Cow,
    fmt::Display,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use ahash::AHashMap;
use chumsky::{
    extra,
    primitive::{any, choice, end, just, one_of},
    text, IterParser, Parser,
};
use rayon::{iter::ParallelIterator, prelude::ParallelBridge};
use serde::{Deserialize, Serialize};
use trust_dns_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{RData, Record, RecordType},
    xfer::DnsResponse,
};
use trust_dns_server::server::Request;

use super::Error;

const DOMAIN_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_*";

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Serialize, PartialEq, Eq, PartialOrd, Deserialize)]
pub struct Rewrite {
    pub v4: IpAddr,
    pub v6: IpAddr,
}

impl Default for Rewrite {
    fn default() -> Self {
        Self {
            v4: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            v6: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, Serialize, PartialEq, Eq, PartialOrd, Deserialize)]
pub(crate) struct Action {
    pub rewrite: Option<Rewrite>,
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, Serialize, PartialEq, Eq, PartialOrd, Deserialize)]
pub enum Kind {
    Allow,
    Deny,
    #[default]
    None,
}

impl Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::None => "None",
        })
    }
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
#[derive(Clone, Default, Serialize, PartialEq, Eq, PartialOrd, Deserialize)]
pub struct Rule {
    pub(crate) domain: String,
    pub(crate) kind: Kind,
    pub(crate) action: Option<Action>,
}

impl Rule {
    fn rule(&self, request: &Request) -> Vec<Record> {
        match request.query().query_type() {
            RecordType::A => vec![
                Record::default()
                    .set_name(request.query().original().name().clone())
                    .set_rr_type(RecordType::A)
                    .set_data(Some(RData::A(
                        match self
                            .action
                            .as_ref()
                            .and_then(|action| action.rewrite.clone())
                            .unwrap_or_default()
                            .v4
                        {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                        },
                    )))
                    .set_ttl(600)
                    .clone(),
            ],
            RecordType::AAAA => vec![
                Record::default()
                    .set_name(request.query().original().name().clone())
                    .set_rr_type(RecordType::AAAA)
                    .set_data(Some(RData::AAAA(
                        match self
                            .action
                            .as_ref()
                            .and_then(|action| action.rewrite.clone())
                            .unwrap_or_default()
                            .v6
                        {
                            IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
                            IpAddr::V6(addr) => addr,
                        },
                    )))
                    .set_ttl(600)
                    .clone(),
            ],
            _ => vec![Record::default()],
        }
    }

    pub fn apply(&self, request: &Request) -> DnsResponse {
        let answers = self.rule(request);

        Message::new()
            .set_header(
                *request
                    .header()
                    .clone()
                    .set_answer_count(answers.len().try_into().unwrap_or_default())
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NoError),
            )
            .add_answers(answers)
            .add_query(request.query().original().clone())
            .clone()
            .into()
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Default, Clone, PartialEq)]
pub struct Rules<'a> {
    pub(crate) children: AHashMap<Cow<'a, str>, Rules<'a>>,
    pub(crate) rule: Option<Rule>,
}

#[cfg(debug_assertions)]
type ParserResult<'a> =
    impl Parser<'a, &'a str, Vec<Option<Type>>, extra::Err<chumsky::prelude::Rich<'a, char>>>;

#[cfg(not(debug_assertions))]
type ParserResult<'a> =
    impl Parser<'a, &'a str, Vec<Option<Type>>, extra::Err<chumsky::prelude::EmptyErr>>;

impl<'a> Rules<'a> {
    fn parser<'b>() -> ParserResult<'b> {
        let comment = one_of("#!")
            .then(any().and_is(text::newline().not()).repeated())
            .padded();

        let eol = comment.ignored().or(text::newline()).or(end()).padded();

        let ipv4 = choice((
            just('1').then(text::digits(10).exactly(2)).slice(),
            just('2')
                .then(just('5').then(text::digits(6).exactly(1)))
                .slice(),
            just('2')
                .then(text::digits(5).exactly(1))
                .then(text::digits(10).exactly(1))
                .slice(),
            text::digits(10).at_least(1).at_most(2).slice(),
        ))
        .separated_by(just('.'))
        .exactly(4)
        .slice();

        let h16 = text::digits(16).at_least(1).at_most(4).slice();
        let ls32 = choice((h16.then(just(':')).then(h16).slice(), ipv4));

        let ipv6 = choice((
            // [ *6( h16 ":" ) h16 ] "::" h16
            // [ *5( h16 ":" ) h16 ] "::" h16
            (h16.then(just(':')).repeated().at_most(6).then(h16))
                .or_not()
                .then(just("::"))
                .then(h16)
                .slice(),
            // [ *4( h16 ":" ) h16 ] "::" ls32
            (h16.then(just(':')).repeated().at_most(4).then(h16))
                .or_not()
                .then(just("::"))
                .then(ls32)
                .slice(),
            // [ *3( h16 ":" ) h16 ] "::" h16 ":" ls32
            (h16.then(just(':')).repeated().at_most(3).then(h16))
                .or_not()
                .then(just("::"))
                .then(h16)
                .then(just(':'))
                .then(ls32)
                .slice(),
            // [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
            (h16.then(just(':')).repeated().at_most(2).then(h16))
                .or_not()
                .then(just("::"))
                .then(h16.then(just(':')).repeated().exactly(2))
                .then(ls32)
                .slice(),
            // [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
            ((h16.then(just(':'))).or_not().then(h16))
                .or_not()
                .then(just("::"))
                .then(h16.then(just(':')).repeated().exactly(3))
                .then(ls32)
                .slice(),
            // [ h16 ] "::" 4( h16 ":" ) ls32
            h16.or_not()
                .then(just("::"))
                .then(h16.then(just(':')).repeated().exactly(4))
                .then(ls32)
                .slice(),
            // "::" 5( h16 ":" ) ls32
            just("::")
                .then(h16.then(just(':')).repeated().exactly(5))
                .then(ls32)
                .slice(),
            // 6( h16 ":" ) ls32
            h16.then(just(':')).repeated().exactly(6).then(ls32).slice(),
            // h16 "::" h16
            // For some reason this isn't handled by any of the above
            // TODO: Make this redundant
            h16.then(just("::")).then(h16).slice(),
        ));

        let ip = choice((ipv4, ipv6))
            .then_ignore(choice((eol, text::whitespace().at_least(1))))
            .from_str::<IpAddr>()
            .unwrapped();

        let domain = one_of(DOMAIN_CHARS)
            .repeated()
            .at_least(1)
            .at_most(63)
            .slice()
            .separated_by(just('.'))
            .at_least(1)
            .collect::<Vec<_>>()
            .map(|a| a.join("."));

        let hosts = ip
            .then_ignore(text::inline_whitespace())
            .then(domain)
            .map(|(ip, domain)| Type::Host(ip, domain));

        let adblock = choice((
            just("@@||").to(Kind::Deny),
            just("||@@").to(Kind::Deny),
            just("||").to(Kind::Allow),
        ))
        .then(choice((ip.map(Type::Ip), domain.map(Type::Domain))))
        .map(|(kind, ty)| Type::Adblock(kind, Box::new(ty)));

        choice((hosts, ip.map(Type::Ip), domain.map(Type::Domain), adblock))
            .map(Some)
            .or(comment.to(None))
            .then_ignore(eol)
            .repeated()
            .collect()
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
            .map_while(Result::ok)
            .par_bridge()
            .try_fold(
                || Vec::with_capacity(1024 * 8),
                |mut rules, line| {
                    let (rules_, errors) = Self::parser().parse(&line).into_output_errors();
                    if errors.is_empty() {
                        rules.extend(rules_.into_iter().flatten().flatten());
                        Ok(rules)
                    } else {
                        println!("{errors:#?}");
                        Err(Error::FilterError(String::from("Invalid filter list")))
                    }
                },
            )
            .try_reduce(
                || Vec::with_capacity(1024 * 64),
                |mut rules, rules_| {
                    rules.extend(rules_);
                    Ok(rules)
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
                current_node
                    .children
                    .entry(Cow::Owned(part.to_string()))
                    .or_default()
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
                    kind: ty,
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

    pub fn merge(&mut self, rules: Rules<'a>) {
        for (child, rules) in rules.children {
            let new = self.children.entry(child).or_default();
            new.rule = rules.rule.clone();
            new.merge(rules);
        }
    }
}

impl<'a> TryFrom<&mut super::List> for Rules<'a> {
    type Error = super::Error;

    fn try_from(value: &mut super::List) -> Result<Self, Self::Error> {
        let mut rules = Self::default();
        let entries = Rules::parse(Path::new(&value.to_string()))?;
        value.entries = rules.insert(entries);

        Ok(rules)
    }
}
