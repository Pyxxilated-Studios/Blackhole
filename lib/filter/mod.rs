use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::Read,
    path::Path,
    sync::LazyLock,
    time::SystemTime,
};

use ahash::AHashSet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::RwLock, task::JoinError};
use tracing::{error, info, instrument};
use trust_dns_server::server::Request;

use crate::{config::Config, metrics, schedule::Sched};

use self::rules::{Rule, Rules};

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
    pub lists: AHashSet<List>,
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
            let _: Result<(), JoinError> = tokio::join!(task).0;
        }
    }

    async fn download(list: List) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        {
            use tracing::debug;
            debug!("Downloading: {list:?}");
        }

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

            let mut writer = OpenOptions::new()
                .create(true)
                .write(true)
                .open(list.to_string())
                .await?;

            match response
                .header("Content-Length")
                .and_then(|s| s.parse::<usize>().ok())
            {
                Some(mut len) => {
                    let mut response = response.into_reader();

                    while len > 0 {
                        let mut bytes = [0; 8192];
                        let length = response.read(&mut bytes).unwrap_or_default();

                        match writer.write_all(&bytes[..length]).await {
                            Err(err) if err.kind() != tokio::io::ErrorKind::Other => {
                                error!("{err}");
                                return Err(err.into());
                            }
                            Err(_) => {
                                break;
                            }
                            _ => {}
                        }

                        len -= length;
                    }
                }
                None => {
                    writer
                        .write_all(response.into_string().unwrap().as_bytes())
                        .await
                        .expect("");
                }
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
        let mut count = 0;
        let rules = {
            let filter = FILTER.read().await;

            filter
                .lists
                .iter()
                .cloned()
                .try_fold(Rules::default(), |mut rules, mut list| {
                    info!("loading filter list: {}", list.name);

                    rules.merge(Rules::try_from(&mut list)?);
                    count += list.entries;

                    info!("Loaded {} filter(s) for {}", list.entries, list.name);

                    Ok::<Rules, Error>(rules)
                })?
        };

        metrics::RULES.set(count.try_into().unwrap());

        FILTER.write().await.rules = rules;

        Ok(())
    }

    ///
    /// Reset the Global Filter to a blank slate. This is mostly useful
    /// when removing filters
    ///
    pub async fn reset(old: Option<Vec<List>>) {
        let lists = if let Some(old_lists) = old {
            old_lists
        } else {
            FILTER.read().await.lists.iter().cloned().collect()
        };

        for list in lists {
            #[cfg(debug_assertions)]
            {
                use tracing::debug;
                debug!("Removing {list:?} ({})", list.to_string());
            }

            std::fs::remove_file(list.to_string()).unwrap_or_default();
        }

        Self::update().await;
        if let Err(err) = Self::import().await {
            error!("{err:#?}");
        }
    }

    pub fn filter(&self, request: &Request) -> Option<Rule> {
        request
            .query()
            .original()
            .name()
            .into_iter()
            .rev()
            .try_fold(&self.rules, |current_node, entry| {
                if let Some(entry) = current_node.children.get(entry) {
                    Ok(entry)
                } else if let Some((_, entry)) = current_node.children.iter().find(|(key, _)| {
                    if !key.contains(&b'*') {
                        return false;
                    }

                    let key = String::from_utf8_lossy(key);
                    let re = REPLACEMENT.replace_all(&key, ".*");
                    let matcher = Regex::new(&re).expect("Failed to parse rule regex");
                    matcher.is_match(&String::from_utf8_lossy(entry))
                }) {
                    Ok(entry)
                } else {
                    Err(current_node)
                }
            })
            .map_or_else(|err| &err.rule, |rule| &rule.rule)
            .clone()
    }

    ///
    /// Check if the request's query matches any of the filters we have.
    ///
    /// # Examples
    ///
    /// ```
    /// use blackhole::filter::Filter;
    /// use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder};
    /// use trust_dns_server::{
    ///    authority::MessageRequest,
    ///    server::{Protocol, Request},
    /// };
    ///
    /// let request = Request::new(
    ///        MessageRequest::read(&mut BinDecoder::new(&[
    ///            0xf6, 0x3d, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x67,
    ///            0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    ///            0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08,
    ///            0xcf, 0xef, 0x93, 0x5b, 0x92, 0xad, 0x6e, 0xdf,
    ///        ]))
    ///        .unwrap(),
    ///     "127.0.0.1:53".parse().unwrap(),
    ///      Protocol::Udp,
    /// );
    ///
    /// assert_eq!(Filter::check(&request), None);
    /// ```
    ///
    /// # Returns
    /// If there is a rule that matches, then Some(rule).
    /// Otherwise, None.
    ///
    pub fn check(request: &Request) -> Option<Rule> {
        // We currently only support A/AAAA query filtering.
        // TODO: Would this be worth expanding?
        if request.query().query_type().is_ip_addr() {
            FILTER
                .try_read()
                .map(|filter| filter.filter(request))
                .unwrap_or_default()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pretty_assertions::assert_eq;
    use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder};
    use trust_dns_server::{
        authority::MessageRequest,
        server::{Protocol, Request},
    };

    use crate::filter::rules::{Kind, Rules};

    use super::Filter;

    #[test]
    fn parsing() {
        let mut filter = Filter::default();

        let entries = Rules::parse(Path::new("benches/test.txt"));
        assert!(entries.is_ok());

        let entries = entries.unwrap();
        assert_eq!(filter.rules.insert(entries), 81562);
    }

    #[test]
    fn checking() {
        let mut filter = Filter::default();

        let request = Request::new(
            MessageRequest::read(&mut BinDecoder::new(&[
                0x9b, 0x09, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00,
                0x08, 0x33, 0x70, 0x1c, 0x9b, 0x66, 0xe1, 0xb6, 0x12,
            ]))
            .unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
        );

        let entries = Rules::parse(Path::new("benches/test.txt")).unwrap();
        filter.rules.insert(entries);

        let rule = filter.filter(&request);
        assert!(rule.is_some());

        let rule = rule.unwrap();
        assert_eq!(rule.kind, Kind::Deny);
    }

    #[test]
    fn regex_matching() {
        let mut filter = Filter::default();

        let request = Request::new(
            MessageRequest::read(&mut BinDecoder::new(&[
                0xf6, 0x3d, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x67,
                0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08,
                0xcf, 0xef, 0x93, 0x5b, 0x92, 0xad, 0x6e, 0xdf,
            ]))
            .unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
        );

        let entries = Rules::parse(Path::new("benches/test.txt")).unwrap();
        filter.rules.insert(entries);

        let rule = filter.filter(&request);
        assert!(rule.is_some());

        let rule = rule.unwrap();
        assert_eq!(rule.kind, Kind::Deny);
        assert_eq!(rule.domain, "*mail.com");
    }
}
