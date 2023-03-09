use clap::Parser;

fn default_config() -> String {
    "/config/blackhole.toml".into()
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Path to the config file",
        default_value_t = default_config()
    )]
    pub config: String,
}
