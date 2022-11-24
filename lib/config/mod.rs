use std::{
    collections::HashSet,
    fmt::Debug,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, instrument};

use crate::{filter::List, schedule::Schedule, server::Upstream};

pub static CONFIG: LazyLock<RwLock<Config>> = LazyLock::new(RwLock::default);
static CONFIG_FILE: LazyLock<RwLock<String>> = LazyLock::new(RwLock::default);

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO Error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Serialisation Error: {0}")]
    Serialization(#[from] toml::ser::Error),
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(alias = "upstream", rename(serialize = "upstream"))]
    pub upstreams: HashSet<Upstream>,
    #[serde(alias = "filter", rename(serialize = "filter"))]
    pub filters: Vec<List>,
    #[serde(alias = "schedule", rename(serialize = "schedule"))]
    pub schedules: Vec<Schedule>,
}

pub trait Load {
    ///
    /// Load a configuration profile, which could be something like
    /// a path (e.g. a configuration file), or CLI arguments
    ///
    /// # Errors
    /// This may error in several cases, which should be documented
    /// in the implementation.
    ///
    async fn load(&self, config: &mut Config) -> std::io::Result<()>;
}

impl Load for PathBuf {
    ///
    /// Load a file (e.g. Configuration file)
    ///
    /// # Errors
    /// Should the file not exist in readable form, this will fail. If the file also
    /// isn't valid toml this will fail.
    ///
    #[instrument(level = "info", ret, err, skip(self, config), fields(file = self.to_str()))]
    async fn load(&self, config: &mut Config) -> std::io::Result<()> {
        *CONFIG_FILE.write().await = self.to_string_lossy().to_string();

        let conf = std::fs::read_to_string(self)?;
        let conf: Config = toml::from_str(&conf)?;

        config.upstreams.extend(conf.upstreams);
        config.filters.extend(conf.filters);
        config.schedules.extend(conf.schedules);

        Ok(())
    }
}

impl Config {
    ///
    /// Load a configuration profile
    ///
    /// # Errors
    /// This can fail if the configuration profile fails to load,
    /// see [`Load`]
    ///
    pub async fn load<C: Load + 'static>(loader: C) -> std::io::Result<()> {
        let mut config = CONFIG.write().await;
        loader.load(&mut config).await?;

        Ok(())
    }

    ///
    /// Save the config to disk
    ///
    /// # Errors
    /// While this should be unlikely, it is possible for this to
    /// result in an error if:
    ///  - There is no disk space left
    ///  - The config file is not writable
    ///
    pub async fn save() -> Result<(), Error> {
        Ok(std::fs::write(
            Path::new(&*CONFIG_FILE.read().await),
            toml::to_string(&*CONFIG.read().await)?,
        )?)
    }

    ///
    /// Retrieve a config variable from the global Configuration
    ///
    pub async fn get<F, T>(func: F) -> T
    where
        F: Fn(&Config) -> T,
    {
        func(&*CONFIG.read().await)
    }

    ///
    /// Set a config variable in the global Configuration
    ///
    /// Note that this also saves the configuration to a file every time
    ///
    /// # Errors
    /// This will result in an error if saving the config to a file does
    ///
    pub async fn set<F>(func: F) -> Result<(), Error>
    where
        F: Fn(&mut Config),
    {
        let old_config = CONFIG.read().await.clone();
        func(&mut *CONFIG.write().await);
        if let Err(err) = Self::save().await {
            error!("{err:?}");
            *CONFIG.write().await = old_config;
            match Self::save().await {
                Ok(_) => Err(err),
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        }
    }
}
