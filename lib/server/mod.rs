use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};

pub mod udp;

fn default_port() -> u16 {
    53
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub ip: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl FromStr for Upstream {
    type Err = String;

    fn from_str(value: &str) -> core::result::Result<Self, Self::Err> {
        match value.split_once(':') {
            Some((ip, port)) => Ok(Upstream {
                ip: ip.parse().map_err(|e| format!("{e}"))?,
                port: port.parse().map_err(|_| "invalid port".to_string())?,
            }),
            None => Ok(Upstream {
                ip: value.parse().map_err(|e| format!("{e}"))?,
                port: default_port(),
            }),
        }
    }
}
