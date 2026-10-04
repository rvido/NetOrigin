////////////////////////////////////////////////////////////
// NetOrigin - A tool for retrieving IP ranges, ASNs, and IP ownership details
// Command-line option parser
//
// Copyright (c) 2026 All rights reserved.
// Author: Richard Vidal-Dorsch
////////////////////////////////////////////////////////////

use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[command(
    author = "Richard Vidal-Dorsch <richard.dorsch@gmail.com>",
    version,
    about = "This tool retrieves IP ranges, ASNs, and IP ownership details.",
    long_about = None)
]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(["google", "company", "asn", "ip"]),
))]
pub struct Args {
    /// Use Google as the target
    #[arg(long)]
    pub google: bool,

    /// Specify a company name as the target
    #[arg(long)]
    pub company: Option<String>,

    /// List AS numbers of a specific company
    #[arg(long, requires = "company")]
    pub asnums: bool,

    /// Retrieve IP ranges for a specific AS number (e.g. AS12345 or 12345)
    #[arg(long)]
    pub asn: Option<String>,

    /// Look up ASN ownership details for a specific IP using IPinfo
    #[arg(long)]
    pub ip: Option<String>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
