use std::path::PathBuf;

use async_trait::async_trait;
use blackhole::{config::Load, server::udp::Upstream};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(
        short,
        long,
        value_name = "PORT",
        help = "Port to have the server listen on",
        default_value_t = 53
    )]
    pub port: u16,

    #[arg(short, long = "upstream", value_name = "UPSTREAM")]
    upstreams: Vec<Upstream>,
}

#[async_trait]
impl Load for Cli {
    async fn load(self, config: &mut blackhole::config::Config) -> std::io::Result<()> {
        config.upstreams.extend(self.upstreams);

        Ok(())
    }
}
