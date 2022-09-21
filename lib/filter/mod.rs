use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader},
    sync::Arc,
};

use lazy_static::lazy_static;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::dns;

lazy_static! {
    pub static ref FILTERS: Arc<RwLock<Filter>> = Arc::default();
}

const COMMENT_CHARS: [char; 2] = ['!', '#'];

#[derive(Debug, Clone, Default, Serialize, PartialEq, PartialOrd)]
pub(crate) struct Action {
    rewrite: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, PartialOrd)]
pub(crate) enum Kind {
    Allow,
    Deny,
    #[default]
    None,
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
    pub(crate) lists: Vec<String>,
    pub(crate) rules: Rules,
}

impl Filter {
    pub fn parse_line(&mut self, line: &str) {
        if COMMENT_CHARS.iter().any(|&c| line.starts_with(c)) {
            return;
        }

        let mut rule = Rule::default();

        if let Some(domain) = line.strip_prefix("||") {
            rule.domain = domain
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || ['-', '_', '.'].contains(ch))
                .collect();
            rule.ty = Kind::Deny;
        } else if let Some(domain) = line.strip_prefix("@@||") {
            rule.domain = domain
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || ['-', '_', '.'].contains(ch))
                .collect();
            rule.ty = Kind::Allow;
        } else {
            rule.domain = line.to_string();
            rule.ty = Kind::Deny;
        }

        let mut current_node = &mut self.rules;

        for domain in rule.domain.split('.').rev() {
            current_node = current_node.children.entry(domain.to_string()).or_default();
        }

        current_node.rule = Some(rule);
    }

    pub fn parse(&mut self, buffer: BufReader<std::fs::File>) {
        self.rules = Rules::default();

        buffer.lines().filter_map(Result::ok).for_each(|line| {
            self.parse_line(&line);
        });
    }

    ///
    /// Load a list into the filter
    ///
    /// # Errors
    /// If it fails to open the list
    ///
    #[instrument(skip(self, list))]
    pub fn load(&mut self, list: &str) -> io::Result<()> {
        info!("loading filter list: {list}");
        let file = std::fs::File::open(list)?;

        self.parse(BufReader::new(file));

        self.lists.push(list.to_string());

        Ok(())
    }

    pub fn check(&self, packet: &dns::packet::Packet) -> Option<Rule> {
        let mut current_node = &self.rules;

        for entry in packet.questions[0].name.name().split('.').rev() {
            match current_node.children.get(entry) {
                Some(entry) => current_node = entry,
                None => break,
            }
        }

        current_node.rule.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Filter, Kind, Rule, Rules};

    #[test]
    fn parsing() {
        let mut filter = Filter::default();

        filter.parse_line("||google.com");
        filter.parse_line("@@||test.com");
        filter.parse_line("example.com");

        //filter.parse_line("0.0.0.0 ads.com");
        //filter.parse_line("s*.com");

        assert_eq!(
            filter.rules,
            Rules {
                children: {
                    let mut inner = HashMap::default();
                    inner.insert(
                        "com".to_string(),
                        Rules {
                            children: {
                                let mut inner = HashMap::default();
                                inner.insert(
                                    "google".to_string(),
                                    Rules {
                                        children: HashMap::default(),
                                        rule: Some(Rule {
                                            domain: "google.com".to_string(),
                                            ty: Kind::Deny,
                                            action: None,
                                        }),
                                    },
                                );
                                inner.insert(
                                    "test".to_string(),
                                    Rules {
                                        children: HashMap::default(),
                                        rule: Some(Rule {
                                            domain: "test.com".to_string(),
                                            ty: Kind::Allow,
                                            action: None,
                                        }),
                                    },
                                );
                                inner.insert(
                                    "example".to_string(),
                                    Rules {
                                        children: HashMap::default(),
                                        rule: Some(Rule {
                                            domain: "example.com".to_string(),
                                            ty: Kind::Deny,
                                            action: None,
                                        }),
                                    },
                                );
                                inner
                            },
                            rule: None,
                        },
                    );
                    inner
                },
                rule: None,
            }
        );
    }
}
