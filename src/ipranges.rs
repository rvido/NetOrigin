////////////////////////////////////////////////////////////
// IP ranges (web-scrapper)
//
// Copyright (c) 2026 All rights reserved.
// Authors: Richard Vidal-Dorsch
////////////////////////////////////////////////////////////

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use reqwest::blocking::Client;
use reqwest::{StatusCode, Url};
use scraper::{Html, Selector};
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

/// ==============================================================================
/// Constants for URLs, timeouts, and other configuration values used in the module.
/// ==============================================================================
///
/// Google IP range URLs (Google Users and Google Cloud) are defined for fetching official IP range data.:
/// Source: https://knowledge.workspace.google.com/admin/security/obtain-google-ip-address-ranges
const URL_GOOGLE_IPS: &str = "https://www.gstatic.com/ipranges/goog.json";
const URL_GOOGLE_CLOUD: &str = "https://www.gstatic.com/ipranges/cloud.json";
/// IPinfo API endpoints for ASN lookup and Lite lookup:
const URL_IPINFO_LOOKUP: &str = "https://api.ipinfo.io/lookup";
const URL_IPINFO_LITE: &str = "https://api.ipinfo.io/lite";
const IPINFO_TOKEN_ENV: &str = "IPINFO_TOKEN";
/// Hurricane Electric BGP toolkit (company search and AS pages):
const URL_BGP_HE: &str = "https://bgp.he.net";
/// Configuration for HTTP client and scraping behavior:
const MAX_AS_FETCH_THREADS: usize = 4;
// Some bgp.he.net search pages take more than 10 seconds to render, so allow a longer
// total time, but give up quickly on hosts that do not answer at all.
const REQUEST_TIMEOUT: u64 = 30; // Seconds
const CONNECT_TIMEOUT: u64 = 10; // Seconds
const REQUEST_RETRY_INTERVAL: usize = 10;
const REQUEST_DELAY_INTERVAL: u64 = 1; // Seconds

// Some websites look for a valid web-browser user-agent
// This string can be retrievd when typing 'what's my user agent' into Google search bar
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0";

/// AS numbers and prefixes on `bgp.he.net` are links inside table cells.
/// Parsed once and shared by all threads.
static TABLE_LINK_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("td a").expect("'td a' is a valid CSS selector"));

#[derive(Deserialize)]
struct Prefix {
    #[serde(rename = "ipv4Prefix", default)]
    ipv4_prefix: Option<String>,

    #[serde(rename = "ipv6Prefix", default)]
    ipv6_prefix: Option<String>,
}

#[derive(Deserialize)]
struct GoogleIpRangeResponse {
    prefixes: Vec<Prefix>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpInfoAsnResponse {
    pub asn: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(rename = "type", default)]
    pub asn_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpInfoLookupResponse {
    pub ip: String,
    #[serde(rename = "as", default)]
    pub asn: Option<IpInfoAsnResponse>,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub continent_code: Option<String>,
    #[serde(default)]
    pub continent: Option<String>,
}

#[derive(Deserialize)]
struct IpInfoLiteLookupResponse {
    ip: String,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    as_name: Option<String>,
    #[serde(default)]
    as_domain: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    continent_code: Option<String>,
    #[serde(default)]
    continent: Option<String>,
}

/// Separates a slice of mixed-version `IpNet` into version-specific `IpRange` collections.
///
/// This function iterates through a slice of `IpNet` and sorts each network into either an
/// `IpRange<Ipv4Net>` or an `IpRange<Ipv6Net>` based on its IP version. This is useful
/// for processing a heterogeneous list of networks into separate, typed collections.
///
/// # Arguments
///
/// * `ipnets` - A slice of `IpNet` containing a mix of IPv4 and IPv6 networks.
///
/// # Returns
///
/// A tuple `(IpRange<Ipv4Net>, IpRange<Ipv6Net>)` where the first element contains all
/// the IPv4 networks and the second contains all the IPv6 networks.
///
/// # Example
/// ```
/// use ipnet::{IpNet, Ipv4Net, Ipv6Net};
/// use netorigin::ipranges::from_ipnet;
///
/// let mixed_nets = vec!["192.0.2.0/24".parse::<Ipv4Net>().unwrap().into(), "2001:db8::/32".parse::<Ipv6Net>().unwrap().into()];
/// let (ipv4_range, ipv6_range) = from_ipnet(&mixed_nets);
///
/// assert_eq!(ipv4_range.iter().count(), 1);
/// assert_eq!(ipv6_range.iter().count(), 1);
/// ```
#[inline]
pub fn from_ipnet(ipnets: &[IpNet]) -> (IpRange<Ipv4Net>, IpRange<Ipv6Net>) {
    let mut ipv4_range = IpRange::new();
    let mut ipv6_range = IpRange::new();

    for ipnet in ipnets.iter() {
        match ipnet {
            IpNet::V4(ipv4) => {
                ipv4_range.add(*ipv4);
            }
            IpNet::V6(ipv6) => {
                ipv6_range.add(*ipv6);
            }
        }
    }

    (ipv4_range, ipv6_range)
}

/// Combines separate vectors of IPv4 and IPv6 networks into a single `Vec<IpNet>`.
///
/// This is a utility function to merge collections of different IP versions into a unified list,
/// which is useful for operations that handle both IPv4 and IPv6 networks generically.
///
/// # Arguments
///
/// * `ipv4_nets` - A `Vec<Ipv4Net>` containing the IPv4 networks.
/// * `ipv6_nets` - A `Vec<Ipv6Net>` containing the IPv6 networks.
///
/// # Returns
///
/// A `Vec<IpNet>` that contains all networks from both input vectors.
///
/// # Example
/// ```
/// use ipnet::{IpNet, Ipv4Net, Ipv6Net};
/// use netorigin::ipranges::to_ipnet;
///
/// let ipv4s = vec!["192.0.2.0/24".parse::<Ipv4Net>().unwrap()];
/// let ipv6s = vec!["2001:db8::/32".parse::<Ipv6Net>().unwrap()];
/// let combined = to_ipnet(&ipv4s, &ipv6s);
/// assert_eq!(combined.len(), 2);
/// ```
#[inline]
pub fn to_ipnet(ipv4_nets: &[Ipv4Net], ipv6_nets: &[Ipv6Net]) -> Vec<IpNet> {
    let mut combined: Vec<IpNet> = Vec::with_capacity(ipv4_nets.len() + ipv6_nets.len());

    // Convert and add IPv4 networks
    combined.extend(ipv4_nets.iter().map(|ipv4| IpNet::V4(*ipv4)));

    // Convert and add IPv6 networks
    combined.extend(ipv6_nets.iter().map(|ipv6| IpNet::V6(*ipv6)));

    combined
}

/// Retrieves the Autonomous System (AS) numbers for a given company.
///
/// This function scrapes `bgp.he.net` to find AS numbers associated with the specified company name.
/// The search URL constructed is:
/// ```text
/// https://bgp.he.net/search?search[search]={company}&commit=Search
/// ```
/// It parses the HTML response to extract AS numbers (e.g., "AS12345"). Duplicates are removed
/// while keeping the order of the search results.
///
/// # Arguments
///
/// * `company` - A string slice (`&str`) representing the company name to search for (e.g., "roblox", "telegram").
///
/// # Returns
///
/// A `Result` containing:
/// - `Ok(Vec<String>)`: A vector of found AS numbers.
/// - `Err(Box<dyn std::error::Error>)`: An error if the HTTP request or parsing fails.
///
/// # Example
/// ```no_run
/// use netorigin::ipranges::get_as_numbers_of;
///
/// let as_numbers = get_as_numbers_of("telegram").unwrap();
/// println!("Telegram AS numbers: {:?}", as_numbers);
/// ```
pub fn get_as_numbers_of(company: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = company_search_url(company)?;
    let client = build_http_client(REQUEST_TIMEOUT, USER_AGENT)?;
    get_as_numbers_from_url(&client, url.as_str())
}

/// Retrieves all IP prefixes announced by a single Autonomous System.
///
/// Accepts the AS number with or without the `AS` prefix (e.g. `"AS12345"` or `"12345"`).
/// The page `https://bgp.he.net/AS{n}` is scraped for announced prefixes.
///
/// # Arguments
///
/// * `asn` - A string slice representing the AS number, e.g. `"AS12345"` or `"12345"`.
///
/// # Returns
///
/// A `Result<Vec<IpNet>, Box<dyn std::error::Error>>` containing all announced prefixes
/// (both IPv4 and IPv6), simplified and sorted.
pub fn get_ip_ranges_for_asn(asn: &str) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    let canonical = canonical_asn(asn)?;
    let client = build_http_client(REQUEST_TIMEOUT, USER_AGENT)?;
    let url = format!("{URL_BGP_HE}/{canonical}");
    let all_ipnets = get_ipranges_from_url(&client, &url)?;

    Ok(aggregate_ipnets(all_ipnets))
}

/// Looks up IP ownership data through the IPinfo API.
///
/// The API token is read from the `IPINFO_TOKEN` environment variable.
/// This lookup returns structured ASN data for a single IP address and is intended
/// as an alternative provider-backed capability alongside the existing scraping-based flows.
pub fn lookup_ipinfo(ip: &str) -> Result<IpInfoLookupResponse, Box<dyn std::error::Error>> {
    let ip: IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| format!("'{ip}' is not a valid IPv4 or IPv6 address"))?;
    let token = env::var(IPINFO_TOKEN_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| format!("{IPINFO_TOKEN_ENV} environment variable is not set"))?;
    let client = build_http_client(REQUEST_TIMEOUT, USER_AGENT)?;
    let response = request_ipinfo_with_fallback(&client, ip, token.trim())?;

    parse_ipinfo_lookup_response(&response)
}

/// The 'Hurricane Electric Internet Services' request URL to search for
/// IP ranges looks like this:
/// ```text
/// https://bgp.he.net/search?search[search]={name}&commit=Search
/// ```
/// This function performs web scraping on `bgp.he.net` to first find AS numbers
/// related to the `company` and then scrapes the individual AS pages to
/// collect and return all associated IPv4 and IPv6 prefixes.
///
/// # Arguments
///
/// * `company` - A string slice (`&str`) representing the company name to search for e.g. roblox, telegram, etc.
///
/// # Returns
///
/// This function returns a `Result<Vec<IpNet>, Box<dyn std::error::Error>>`.
/// - `Ok(Vec<IpNet>)`: A vector containing all collected IP prefixes (both IPv4 and IPv6) on success.
/// - `Err(Box<dyn std::error::Error>)`: An error object if any of the web scraping or parsing
///   operations fail.
pub fn get_ip_ranges_of(company: &str) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    let url = company_search_url(company)?;
    let client = build_http_client(REQUEST_TIMEOUT, USER_AGENT)?;

    // First, get the AS numbers associated with the given company.
    let asnums = get_as_numbers_from_url(&client, url.as_str())?;
    if asnums.is_empty() {
        return Ok(Vec::new());
    }

    // Fetch prefixes from each AS page in parallel.
    let pool = ThreadPoolBuilder::new()
        .num_threads(MAX_AS_FETCH_THREADS.min(asnums.len()))
        .build()?;

    let fetched = pool.install(|| {
        asnums
            .par_iter()
            .map(|asnum| {
                let url = format!("{URL_BGP_HE}/{asnum}");
                get_ipranges_from_url(&client, &url).map_err(|err| format!("{asnum}: {err}"))
            })
            .collect::<Result<Vec<_>, _>>()
    })?;

    // Combine adjacent or overlapping IP ranges, then sort them
    Ok(aggregate_ipnets(fetched.into_iter().flatten()))
}

/// Retrieves Google's non-cloud service IP ranges.
///
/// This function fetches two lists of IP ranges from Google's official sources:
/// 1. The general list of all Google IP ranges (`goog.json`).
/// 2. The list of Google Cloud IP ranges (`cloud.json`).
///
/// It then subtracts the Cloud ranges from the general list to produce a set of IP ranges
/// used by Google's services (like Search, Gmail, etc.), excluding Google Cloud infrastructure.
/// The resulting ranges are simplified to merge adjacent networks and then sorted.
///
/// # Returns
///
/// A `Result` which is:
/// - `Ok((Vec<Ipv4Net>, Vec<Ipv6Net>))`: A tuple containing two vectors. The first vector
///   holds the sorted IPv4 network ranges, and the second holds the sorted IPv6 network ranges.
/// - `Err(Box<dyn std::error::Error>)`: An error if fetching or parsing the IP range data fails.
///
/// # Example
/// ```no_run
/// use netorigin::ipranges;
///
/// if let Ok((ipv4_ranges, ipv6_ranges)) = ipranges::get_google_ip_ranges() {
///     println!("Found {} IPv4 and {} IPv6 ranges for Google services.",
///              ipv4_ranges.len(),
///              ipv6_ranges.len());
///     // You can then iterate over ipv4_ranges and ipv6_ranges
/// }
/// ```
pub fn get_google_ip_ranges() -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), Box<dyn std::error::Error>> {
    let client = build_http_client(REQUEST_TIMEOUT, USER_AGENT)?;

    // Both feeds are independent, so fetch them at the same time.
    let (google_response, cloud_response) = std::thread::scope(|scope| {
        let cloud = scope.spawn(|| {
            request_ip_range_list(&client, URL_GOOGLE_CLOUD)
                .map_err(|err| format!("google cloud ip ranges: {err}"))
        });
        let google = request_ip_range_list(&client, URL_GOOGLE_IPS)
            .map_err(|err| format!("google ip ranges: {err}"));
        let cloud = cloud
            .join()
            .unwrap_or_else(|_| Err("google cloud ip ranges: fetch thread panicked".to_string()));
        (google, cloud)
    });

    let (mut goog_ip4, mut goog_ip6) = to_iprange(&google_response?)?;
    let (cloud_ip4, cloud_ip6) = to_iprange(&cloud_response?)?;

    cloud_ip4.iter().for_each(|ip4| {
        goog_ip4.remove(ip4);
    });
    cloud_ip6.iter().for_each(|ip6| {
        goog_ip6.remove(ip6);
    });

    Ok(simplify_and_sort(goog_ip4, goog_ip6))
}

///////////////////////////////////////////////////////////////////////////////
//
// Helper function to perform HTTP GET request and parse the JSON response
//
///////////////////////////////////////////////////////////////////////////////

#[inline]
fn request_ip_range_list(
    client: &Client,
    url: &str,
) -> Result<GoogleIpRangeResponse, Box<dyn std::error::Error>> {
    let response = get_html_content(client, url)?;
    let result: GoogleIpRangeResponse = serde_json::from_str(response.as_str())?;

    Ok(result)
}

#[inline]
fn parse_ipinfo_lookup_response(
    response: &str,
) -> Result<IpInfoLookupResponse, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(response)?;

    if value.get("as").is_some() {
        let core: IpInfoLookupResponse = serde_json::from_value(value)?;
        return Ok(core);
    }

    if value.get("asn").is_some() || value.get("as_name").is_some() {
        let lite: IpInfoLiteLookupResponse = serde_json::from_value(value)?;
        let mapped = IpInfoLookupResponse {
            ip: lite.ip,
            asn: lite.asn.map(|asn| IpInfoAsnResponse {
                asn,
                name: lite.as_name,
                domain: lite.as_domain,
                route: None,
                asn_type: None,
            }),
            country_code: lite.country_code,
            country: lite.country,
            continent_code: lite.continent_code,
            continent: lite.continent,
        };
        return Ok(mapped);
    }

    let core: IpInfoLookupResponse = serde_json::from_value(value)?;
    Ok(core)
}

#[inline]
fn request_ipinfo_with_fallback(
    client: &Client,
    ip: IpAddr,
    token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Send the token as a header, not in the URL, so it never shows up in error messages.
    let core_response = client
        .get(format!("{URL_IPINFO_LOOKUP}/{ip}"))
        .bearer_auth(token)
        .send()?;

    if core_response.status().is_success() {
        return core_response.text().map_err(Into::into);
    }

    // Lite tokens can be rejected by /lookup. Fall back to the Lite endpoint.
    if core_response.status() == StatusCode::FORBIDDEN {
        let lite_response = client
            .get(format!("{URL_IPINFO_LITE}/{ip}"))
            .bearer_auth(token)
            .send()?;

        if lite_response.status().is_success() {
            return lite_response.text().map_err(Into::into);
        }

        let status = lite_response.status();
        let body = lite_response.text().unwrap_or_default();
        return Err(format!("IPinfo Lite request failed: {status} {body}").into());
    }

    let status = core_response.status();
    let body = core_response.text().unwrap_or_default();
    Err(format!("IPinfo lookup request failed: {status} {body}").into())
}

/// Returns a tuple containing Ipv4 and Ipv6 addresses ranges
#[inline]
fn to_iprange(
    response: &GoogleIpRangeResponse,
) -> Result<(IpRange<Ipv4Net>, IpRange<Ipv6Net>), Box<dyn std::error::Error>> {
    let mut ipv4nets = IpRange::new();
    let mut ipv6nets = IpRange::new();

    for prefix in response.prefixes.iter() {
        if let Some(ipv4) = &prefix.ipv4_prefix {
            let net: Ipv4Net = ipv4
                .trim()
                .parse()
                .map_err(|err| format!("invalid IPv4 prefix '{ipv4}': {err}"))?;
            ipv4nets.add(net);
        }
        if let Some(ipv6) = &prefix.ipv6_prefix {
            let net: Ipv6Net = ipv6
                .trim()
                .parse()
                .map_err(|err| format!("invalid IPv6 prefix '{ipv6}': {err}"))?;
            ipv6nets.add(net);
        }
    }

    Ok((ipv4nets, ipv6nets))
}

/// Merges adjacent or overlapping prefixes and returns them sorted.
#[inline]
fn simplify_and_sort(
    mut ipv4: IpRange<Ipv4Net>,
    mut ipv6: IpRange<Ipv6Net>,
) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
    ipv4.simplify();
    ipv6.simplify();

    let mut ipv4nets = ipv4.iter().collect::<Vec<_>>();
    let mut ipv6nets = ipv6.iter().collect::<Vec<_>>();
    ipv4nets.sort_unstable();
    ipv6nets.sort_unstable();

    (ipv4nets, ipv6nets)
}

/// Simplifies a mixed list of prefixes: IPv4 first, then IPv6, each sorted.
#[inline]
fn aggregate_ipnets(ipnets: impl IntoIterator<Item = IpNet>) -> Vec<IpNet> {
    let mut ipv4 = IpRange::new();
    let mut ipv6 = IpRange::new();

    for ipnet in ipnets {
        match ipnet {
            IpNet::V4(net) => {
                ipv4.add(net);
            }
            IpNet::V6(net) => {
                ipv6.add(net);
            }
        }
    }

    let (ipv4nets, ipv6nets) = simplify_and_sort(ipv4, ipv6);
    to_ipnet(&ipv4nets, &ipv6nets)
}

/// Builds the `bgp.he.net` search URL with the company name safely URL-encoded.
#[inline]
fn company_search_url(company: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let company = company.trim();
    if company.is_empty() {
        return Err("company name must not be empty".into());
    }

    Url::parse_with_params(
        &format!("{URL_BGP_HE}/search"),
        &[("search[search]", company), ("commit", "Search")],
    )
    .map_err(Into::into)
}

/// Accepts `"AS12345"`, `"as12345"` or `"12345"` and returns `"AS12345"`.
#[inline]
fn canonical_asn(asn: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = asn.trim();
    let digits = match trimmed.get(..2) {
        Some(prefix) if prefix.eq_ignore_ascii_case("AS") => &trimmed[2..],
        _ => trimmed,
    };

    match digits.parse::<u32>() {
        Ok(number) if digits.bytes().all(|b| b.is_ascii_digit()) => Ok(format!("AS{number}")),
        _ => {
            Err(format!("'{asn}' is not a valid AS number (expected e.g. AS12345 or 12345)").into())
        }
    }
}

/// Returns `true` for strings like `"AS12345"`.
#[inline]
fn is_as_number(entry: &str) -> bool {
    entry
        .strip_prefix("AS")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

#[inline]
fn get_as_numbers_from_url(
    client: &Client,
    url: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let scraped = scrape_website(client, url, &TABLE_LINK_SELECTOR)?;
    Ok(unique_as_numbers(scraped))
}

/// Keeps only AS numbers and drops duplicates, keeping the first-seen order.
#[inline]
fn unique_as_numbers(entries: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|entry| is_as_number(entry) && seen.insert(entry.clone()))
        .collect()
}

#[inline]
fn get_ipranges_from_url(
    client: &Client,
    url: &str,
) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    let scraped_prefixes = scrape_website(client, url, &TABLE_LINK_SELECTOR)?;
    let ipnets = scraped_prefixes
        .into_iter()
        .filter_map(|ip| ip.parse::<IpNet>().ok())
        .collect::<Vec<_>>();
    Ok(ipnets)
}

#[inline]
fn build_http_client(timeout: u64, user_agent: &str) -> Result<Client, Box<dyn std::error::Error>> {
    Client::builder()
        .user_agent(user_agent)
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(Into::into)
}

#[inline]
fn get_html_content(client: &Client, url: &str) -> Result<String, Box<dyn std::error::Error>> {
    http_get_retry_timeout(client, url, REQUEST_RETRY_INTERVAL, REQUEST_DELAY_INTERVAL)
}

#[inline]
fn scrape_website(
    client: &Client,
    url: &str,
    selector: &Selector,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let html_content = get_html_content(client, url)?;
    Ok(extract_texts(&html_content, selector))
}

/// Returns the trimmed text of every element that matches `selector`.
#[inline]
fn extract_texts(html: &str, selector: &Selector) -> Vec<String> {
    Html::parse_document(html)
        .select(selector)
        .map(|e| e.text().collect::<String>().trim().to_owned())
        .filter(|text| !text.is_empty())
        .collect()
}

/// `429 Too Many Requests` and `408 Request Timeout` are temporary, so they are retried.
#[inline]
fn is_retryable_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
}

#[inline]
fn http_get_retry_timeout(
    client: &Client,
    url: &str,
    retry: usize,
    delay: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let retry = retry.max(1);
    let delay = Duration::from_secs(delay);
    let mut last_error = String::new();

    for attempt in 1..=retry {
        match client.get(url).send() {
            Ok(response) if response.status().is_success() => match response.text() {
                Ok(body) => return Ok(body),
                // The body can time out or break off; that is worth another try.
                Err(err) => last_error = format!("reading response body failed: {err}"),
            },
            Ok(response) if !is_retryable_status(response.status()) => {
                return Err(format!("Request error: {} ({url})", response.status()).into());
            }
            Ok(response) => last_error = format!("HTTP {}", response.status()),
            Err(err) => last_error = err.to_string(),
        }

        if attempt < retry {
            std::thread::sleep(delay);
        }
    }

    Err(format!("{url}: no successful response after {retry} attempts: {last_error}").into())
}

///////////////////////////////////////////////////////////////////////////////
//
// Unit tests for the ipranges module
//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_google_response() -> GoogleIpRangeResponse {
        GoogleIpRangeResponse {
            prefixes: vec![
                Prefix {
                    ipv4_prefix: Some("192.0.2.0/24".to_string()),
                    ipv6_prefix: None,
                },
                Prefix {
                    ipv4_prefix: None,
                    ipv6_prefix: Some("2001:db8::/32".to_string()),
                },
                Prefix {
                    ipv4_prefix: Some("198.51.100.0/24".to_string()),
                    ipv6_prefix: None,
                },
                Prefix {
                    ipv4_prefix: None,
                    ipv6_prefix: None,
                },
            ],
        }
    }

    fn sample_ipinfo_response() -> &'static str {
        r#"{
            "ip": "8.8.8.8",
            "as": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "8.8.8.0/24",
                "type": "hosting"
            }
        }"#
    }

    fn sample_ipinfo_lite_response() -> &'static str {
        r#"{
            "ip": "8.8.8.8",
            "asn": "AS15169",
            "as_name": "Google LLC",
            "as_domain": "google.com",
            "country_code": "US",
            "country": "United States",
            "continent_code": "NA",
            "continent": "North America"
        }"#
    }

    #[test]
    fn test_from_ipnet() {
        let mixed_nets: Vec<IpNet> = vec![
            "192.0.2.0/24".parse::<Ipv4Net>().unwrap().into(),
            "2001:db8::/32".parse::<Ipv6Net>().unwrap().into(),
            "2001:db8:1::/48".parse::<Ipv6Net>().unwrap().into(),
        ];
        let (ipv4, ipv6) = from_ipnet(&mixed_nets);
        assert_eq!(ipv4.iter().count(), 1);
        assert_eq!(ipv6.iter().count(), 1);
    }
    #[test]
    fn test_to_ipnet() {
        let ipv4s = vec![
            "192.0.2.0/24".parse::<Ipv4Net>().unwrap(),
            "203.0.113.0/24".parse::<Ipv4Net>().unwrap(),
        ];
        let ipv6s = vec!["2001:db8::/32".parse::<Ipv6Net>().unwrap()];
        let combined = to_ipnet(&ipv4s, &ipv6s);
        assert_eq!(combined.len(), 3);
    }

    #[test]
    fn test_to_iprange_separates_ipv4_and_ipv6_prefixes() {
        let response = sample_google_response();

        let (ipv4, ipv6) = to_iprange(&response).unwrap();

        let ipv4nets = ipv4.iter().collect::<Vec<_>>();
        let ipv6nets = ipv6.iter().collect::<Vec<_>>();

        assert_eq!(ipv4nets.len(), 2);
        assert_eq!(ipv6nets.len(), 1);
        assert!(ipv4nets.contains(&"192.0.2.0/24".parse::<Ipv4Net>().unwrap()));
        assert!(ipv4nets.contains(&"198.51.100.0/24".parse::<Ipv4Net>().unwrap()));
        assert_eq!(ipv6nets[0], "2001:db8::/32".parse::<Ipv6Net>().unwrap());
    }

    #[test]
    fn test_to_iprange_ignores_empty_prefix_entries() {
        let response = GoogleIpRangeResponse {
            prefixes: vec![Prefix {
                ipv4_prefix: None,
                ipv6_prefix: None,
            }],
        };

        let (ipv4, ipv6) = to_iprange(&response).unwrap();

        assert_eq!(ipv4.iter().count(), 0);
        assert_eq!(ipv6.iter().count(), 0);
    }

    #[test]
    fn test_parse_ipinfo_lookup_response_extracts_asn_details() {
        let response = parse_ipinfo_lookup_response(sample_ipinfo_response()).unwrap();

        assert_eq!(response.ip, "8.8.8.8");

        let asn = response.asn.unwrap();
        assert_eq!(asn.asn, "AS15169");
        assert_eq!(asn.name.as_deref(), Some("Google LLC"));
        assert_eq!(asn.domain.as_deref(), Some("google.com"));
        assert_eq!(asn.route.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(asn.asn_type.as_deref(), Some("hosting"));
    }

    #[test]
    fn test_parse_ipinfo_lookup_response_handles_missing_asn() {
        let response = parse_ipinfo_lookup_response(r#"{"ip":"127.0.0.1","bogon":true}"#).unwrap();

        assert_eq!(response.ip, "127.0.0.1");
        assert!(response.asn.is_none());
    }

    #[test]
    fn test_parse_ipinfo_lookup_response_supports_lite_schema() {
        let response = parse_ipinfo_lookup_response(sample_ipinfo_lite_response()).unwrap();

        assert_eq!(response.ip, "8.8.8.8");

        let asn = response.asn.unwrap();
        assert_eq!(asn.asn, "AS15169");
        assert_eq!(asn.name.as_deref(), Some("Google LLC"));
        assert_eq!(asn.domain.as_deref(), Some("google.com"));
        assert!(asn.route.is_none());
        assert!(asn.asn_type.is_none());
        assert_eq!(response.country_code.as_deref(), Some("US"));
        assert_eq!(response.country.as_deref(), Some("United States"));
        assert_eq!(response.continent_code.as_deref(), Some("NA"));
        assert_eq!(response.continent.as_deref(), Some("North America"));
    }

    #[test]
    fn test_to_iprange_rejects_invalid_prefix() {
        let response = GoogleIpRangeResponse {
            prefixes: vec![Prefix {
                ipv4_prefix: Some("not-a-cidr".to_string()),
                ipv6_prefix: None,
            }],
        };

        assert!(to_iprange(&response).is_err());
    }

    #[test]
    fn test_aggregate_ipnets_merges_and_sorts() {
        let nets: Vec<IpNet> = vec![
            "2001:db8::/33".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
            "192.0.2.128/25".parse().unwrap(),
            "192.0.2.0/25".parse().unwrap(),
            "2001:db8:8000::/33".parse().unwrap(),
        ];

        let result = aggregate_ipnets(nets);

        let expected: Vec<IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_canonical_asn() {
        assert_eq!(canonical_asn("AS15169").unwrap(), "AS15169");
        assert_eq!(canonical_asn("as15169").unwrap(), "AS15169");
        assert_eq!(canonical_asn(" 15169 ").unwrap(), "AS15169");
        assert!(canonical_asn("").is_err());
        assert!(canonical_asn("AS").is_err());
        assert!(canonical_asn("AS+1").is_err());
        assert!(canonical_asn("AS1/../x").is_err());
        assert!(canonical_asn("99999999999").is_err());
    }

    #[test]
    fn test_company_search_url_encodes_name() {
        let url = company_search_url(" AT&T #1 ").unwrap();
        assert_eq!(
            url.as_str(),
            "https://bgp.he.net/search?search%5Bsearch%5D=AT%26T+%231&commit=Search"
        );
        assert!(company_search_url("   ").is_err());
    }

    #[test]
    fn test_unique_as_numbers_filters_and_dedups() {
        let entries = ["AS13414", "1.2.3.0/24", "AS62041", "AS13414", "ASX", "AS"]
            .map(String::from)
            .to_vec();

        assert_eq!(unique_as_numbers(entries), vec!["AS13414", "AS62041"]);
    }

    #[test]
    fn test_extract_texts_reads_table_links() {
        let html = r#"<table>
            <tr><td><a href="/AS62041">AS62041</a></td><td>Telegram</td></tr>
            <tr><td><a href="/net/91.108.4.0/22"> <b>91.108.4.0/22</b> </a></td></tr>
            <tr><td><a href="/x"></a></td></tr>
        </table>
        <a href="/AS1">AS1</a>"#;

        assert_eq!(
            extract_texts(html, &TABLE_LINK_SELECTOR),
            vec!["AS62041", "91.108.4.0/22"]
        );
    }

    #[test]
    fn test_lookup_ipinfo_rejects_invalid_ip() {
        let err = lookup_ipinfo("not-an-ip").unwrap_err();
        assert!(err.to_string().contains("not a valid"));
    }

    #[test]
    fn test_get_as_numbers_of() {
        let as_numbers = get_as_numbers_of("telegram").unwrap();
        assert!(!as_numbers.is_empty());
    }
    #[test]
    fn test_get_ip_ranges_of() {
        let ip_ranges = get_ip_ranges_of("telegram").unwrap();
        assert!(!ip_ranges.is_empty());
    }
    #[test]
    fn test_get_google_ip_ranges() {
        let (ipv4, ipv6) = get_google_ip_ranges().unwrap();
        assert!(!ipv4.is_empty());
        assert!(!ipv6.is_empty());
    }
}
