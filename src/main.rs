////////////////////////////////////////////////////////////
// Get IP ranges of a given company or application name
//
// Copyright (c) 2026 All rights reserved.
// Author: Richard Vidal-Dorsch
////////////////////////////////////////////////////////////

mod cli;
mod ipranges;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::parse_args();

    if args.google {
        let (ipv4, ipv6) = ipranges::get_google_ip_ranges()?;
        println!(
            "IP ranges for 'Google Services' ({}):",
            ipv4.len() + ipv6.len()
        );
        println!("# IPv4: {}, #IPv6: {}", ipv4.len(), ipv6.len());
        ipv4.iter().for_each(|ip| println!("{}", ip.to_string()));
        ipv6.iter().for_each(|ip| println!("{}", ip.to_string()));
    } else if let Some(ip) = args.ip {
        let response = ipranges::lookup_ipinfo(ip.as_str())?;
        println!("IPinfo lookup for '{}':", response.ip);

        let print_field = |label: &str, value: &Option<String>| {
            if let Some(v) = value {
                println!("{}: {}", label, v);
            }
        };

        if let Some(asn) = &response.asn {
            println!("ASN: {}", asn.asn);
            print_field("Name", &asn.name);
            print_field("Domain", &asn.domain);
            print_field("Route", &asn.route);
            print_field("Type", &asn.asn_type);
        }
        print_field("Country Code", &response.country_code);
        print_field("Country", &response.country);
        print_field("Continent Code", &response.continent_code);
        print_field("Continent", &response.continent);
    } else if let Some(asn) = args.asn {
        let ip_ranges = ipranges::get_ip_ranges_for_asn(asn.as_str())?;
        println!("IP ranges for '{}' ({}):", asn, ip_ranges.len());
        ip_ranges.iter().for_each(|ip| println!("{}", ip));
    } else if let Some(company) = args.company {
        if args.asnums {
            let as_numbers = ipranges::get_as_numbers_of(company.as_str())?;
            println!("AS numbers for '{}' ({}):", company, as_numbers.len());
            as_numbers.iter().for_each(|asnum| println!("  {}", asnum));
            return Ok(());
        } else {
            let ip_ranges = ipranges::get_ip_ranges_of(company.as_str())?;
            println!("IP ranges for '{}' ({}):", company, ip_ranges.len());
            ip_ranges
                .iter()
                .for_each(|ip_range| println!("  {}", ip_range));
        }
    }

    Ok(())
}
