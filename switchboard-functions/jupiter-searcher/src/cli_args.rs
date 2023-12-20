//! Module define CLI structure.

use clap::{Parser, Subcommand};
use std::env;

/// CLI arguments.
#[derive(Parser, Debug)]
#[clap(name = "mpl-fixed-price-sale-cli")]
#[clap(about = "CLI utility for mpl-fixed-price-sale program")]
#[clap(version, author)]
pub struct CliArgs {
    /// RPC endpoint.
    #[clap(short, long, default_value_t = env::var("ANCHOR_PROVIDER_URL").unwrap(), value_name = "URL")]
    pub url: String,

    /// Path to transaction payer keypair file.
    #[clap(short, long, default_value_t = format!("{}/.config/solana/id.json", env::var("HOME").unwrap()), value_name = "FILE")]
    pub payer_keypair: String,

}