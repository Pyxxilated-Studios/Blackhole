use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader},
    sync::Arc,
};

use lazy_static::lazy_static;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::dns;

lazy_static! {
    pub static ref FILTERS: Arc<RwLock<Filter>> = Arc::default();
}

const COMMENT_CHARS: [char; 2] = ['!', '#'];

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Action {}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) enum Kind {
    Allow,
    Deny,
    #[default]
    None,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Rule {
    pub(crate) domain: String,
    pub(crate) ty: Kind,
    pub(crate) action: Option<Action>,
}

#[derive(Default, Debug, Clone)]
pub struct Rules {
    children: HashMap<String, Rules>,
    rule: Option<Rule>,
}

#[derive(Default, Debug)]
pub struct Filter {
    lists: Vec<String>,
    rules: Rules,
}

impl Filter {
    pub fn parse_line(&mut self, line: &str) {
        if COMMENT_CHARS.iter().any(|&c| line.starts_with(c)) {
            return;
        }

        let mut rule = Rule::default();

        if line.starts_with("||") {
            rule.domain = line[2..].to_string();
            rule.ty = Kind::Deny;
        } else if line.starts_with("@@||") {
            rule.domain = line[4..]
                .to_string()
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
            current_node = current_node
                .children
                .entry(domain.to_string())
                .or_insert(Rules::default());
        }

        current_node.rule = Some(rule);
    }

    pub fn parse(&mut self, buffer: BufReader<std::fs::File>) {
        self.rules = Rules::default();

        buffer.lines().filter_map(Result::ok).for_each(|line| {
            self.parse_line(&line);
        });
    }

    pub fn load(&mut self, list: &str) -> io::Result<()> {
        let file = std::fs::File::open(list)?;

        self.parse(BufReader::new(file));

        self.lists.push(list.to_string());

        // println!("{:#?}", self.rules);
        // println!("{:#?}", self.lists);

        Ok(())
    }

    // pub fn refresh(&mut self) -> io::Result<()> {
    //     self.lists.iter().try_for_each(|file| self.load(&file))
    // }

    pub fn check(&self, packet: &dns::packet::Packet) -> Option<Rule> {
        let mut current_node = &self.rules;

        for entry in packet.questions[0].name.name().split('.').rev() {
            match current_node.children.get(entry) {
                Some(entry) => current_node = entry,
                None => {
                    return current_node.rule.clone();
                }
            }
        }

        current_node.rule.clone()
    }
}
