use std::path::PathBuf;

use clap::Parser;

use blackhole::{
    config::{Error, Load},
    server::Upstream,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", help = "Path to the config file")]
    pub config: Option<PathBuf>,

    #[arg(
        short,
        long,
        value_name = "PORT",
        help = "Port to have the server listen on"
    )]
    pub port: Option<u16>,

    #[arg(short, long = "upstream", value_name = "UPSTREAM")]
    upstreams: Vec<Upstream>,
}

impl Load for Cli {
    #[allow(clippy::unused_async)]
    async fn load(&self, config: &mut blackhole::config::Config) -> Result<(), Error> {
        config.upstreams.extend(self.upstreams.clone());
        if let Some(port) = self.port {
            config.port = port;
        }

        Ok(())
    }
}
