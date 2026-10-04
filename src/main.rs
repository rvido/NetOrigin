////////////////////////////////////////////////////////////
// Get IP ranges of a given company or application name
//
// Copyright (c) 2026 All rights reserved.
// Author: Richard Vidal-Dorsch
////////////////////////////////////////////////////////////

mod cli;

use netorigin::ipranges;
use std::error::Error;
use std::io::{self, BufWriter, Write};

fn main() -> Result<(), Box<dyn Error>> {
    let args = cli::parse_args();

    // Results can be thousands of lines, so buffer stdout instead of flushing per line.
    let mut out = BufWriter::new(io::stdout().lock());
    let result = run(args, &mut out).and_then(|()| out.flush().map_err(Into::into));

    match result {
        // The reader went away (e.g. `| head`); that is not an error.
        Err(err) if is_broken_pipe(err.as_ref()) => Ok(()),
        other => other,
    }
}

fn is_broken_pipe(err: &(dyn Error + 'static)) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::BrokenPipe)
}

fn run(args: cli::Args, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    if args.google {
        let (ipv4, ipv6) = ipranges::get_google_ip_ranges()?;
        writeln!(
            out,
            "IP ranges for 'Google Services' ({}):",
            ipv4.len() + ipv6.len()
        )?;
        writeln!(out, "# IPv4: {}, #IPv6: {}", ipv4.len(), ipv6.len())?;
        for ip in &ipv4 {
            writeln!(out, "{ip}")?;
        }
        for ip in &ipv6 {
            writeln!(out, "{ip}")?;
        }
    } else if let Some(ip) = args.ip {
        let response = ipranges::lookup_ipinfo(ip.as_str())?;
        writeln!(out, "IPinfo lookup for '{}':", response.ip)?;

        let mut print_field = |label: &str, value: &Option<String>| -> io::Result<()> {
            if let Some(v) = value {
                writeln!(out, "{label}: {v}")?;
            }
            Ok(())
        };

        if let Some(asn) = &response.asn {
            print_field("ASN", &Some(asn.asn.clone()))?;
            print_field("Name", &asn.name)?;
            print_field("Domain", &asn.domain)?;
            print_field("Route", &asn.route)?;
            print_field("Type", &asn.asn_type)?;
        }
        print_field("Country Code", &response.country_code)?;
        print_field("Country", &response.country)?;
        print_field("Continent Code", &response.continent_code)?;
        print_field("Continent", &response.continent)?;
    } else if let Some(asn) = args.asn {
        let ip_ranges = ipranges::get_ip_ranges_for_asn(asn.as_str())?;
        writeln!(out, "IP ranges for '{}' ({}):", asn, ip_ranges.len())?;
        for ip in &ip_ranges {
            writeln!(out, "{ip}")?;
        }
    } else if let Some(company) = args.company {
        if args.asnums {
            let as_numbers = ipranges::get_as_numbers_of(company.as_str())?;
            writeln!(out, "AS numbers for '{}' ({}):", company, as_numbers.len())?;
            for asnum in &as_numbers {
                writeln!(out, "  {asnum}")?;
            }
        } else {
            let ip_ranges = ipranges::get_ip_ranges_of(company.as_str())?;
            writeln!(out, "IP ranges for '{}' ({}):", company, ip_ranges.len())?;
            for ip_range in &ip_ranges {
                writeln!(out, "  {ip_range}")?;
            }
        }
    }

    Ok(())
}
