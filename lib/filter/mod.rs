use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader},
    sync::Arc,
};

use lazy_static::lazy_static;
use tokio::sync::RwLock;

use crate::dns;

lazy_static! {
    pub static ref FILTERS: Arc<RwLock<Filter>> = Arc::default();
}

const COMMENT_CHARS: [char; 2] = ['!', '#'];

#[derive(Debug, Clone, Default)]
pub(crate) struct Action {}

#[derive(Debug, Clone, Default)]
pub(crate) enum Kind {
    Allow,
    Deny,
    #[default]
    None,
}

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub(crate) domain: String,
    pub(crate) ty: Kind,
    pub(crate) action: Action,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct List {
    rules: Vec<Rule>,
}

#[derive(Default, Debug)]
pub struct Filter {
    lists: HashMap<String, List>,
}

impl Filter {
    pub fn parse_line(line: &str) -> Option<Rule> {
        if COMMENT_CHARS.iter().any(|&c| line.starts_with(c)) {
            return None;
        }

        let mut rule = Rule::default();

        if line.starts_with("||") {
            rule.domain = line[2..].to_string();
            rule.ty = Kind::Deny;
        } else if line.starts_with("@@||") {
            rule.domain = line[4..].to_string();
            rule.ty = Kind::Allow;
        }

        Some(rule)
    }

    pub fn parse(&mut self, buffer: BufReader<std::fs::File>) -> io::Result<()> {
        let rules = buffer
            .lines()
            .filter_map(|line| {
                if let Ok(line) = line {
                    Filter::parse_line(&line)
                } else {
                    None
                }
            })
            .collect();

        *self.lists.entry("test".to_string()).or_default() = List { rules };

        Ok(())
    }

    pub fn load(&mut self, list: &str) -> io::Result<()> {
        let file = std::fs::File::open(list)?;

        self.parse(BufReader::new(file))
    }

    pub fn refresh(&mut self) -> io::Result<()> {
        let files = self
            .lists
            .iter()
            .map(|(file, _)| file.clone())
            .collect::<Vec<_>>();

        files.iter().try_for_each(|file| self.load(&file))
    }

    pub fn check(&self, packet: &dns::packet::Packet) -> Option<Rule> {
        for (_, list) in &self.lists {
            if let Some(rule) = list.rules.iter().find(|filt| match filt.ty {
                Kind::Allow | Kind::Deny => packet
                    .questions
                    .iter()
                    .any(|question| question.name.name() == filt.domain),
                _ => false,
            }) {
                return Some(rule.clone());
            }
        }

        None
    }
}
