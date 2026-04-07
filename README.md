# NetOrigin

`NetOrigin` is a small Rust CLI for retrieving network ownership data and IP ranges.

It supports:

- Google service IP ranges from Google's published JSON feeds
- Company-to-ASN lookup via `bgp.he.net`
- Company-to-IP-range aggregation via `bgp.he.net`
- ASN-to-IP-range lookup via `bgp.he.net`
- IP-to-ASN ownership lookup via IPinfo

## Requirements

- Rust toolchain with Cargo
- Network access for live lookups
- `IPINFO_TOKEN` environment variable when using `--ip`

## Build

```bash
cargo check
```

## Test

```bash
cargo test
```

## Usage

```bash
cargo run -- --google
cargo run -- --company telegram
cargo run -- --company telegram --asnums
cargo run -- --asn AS15169
cargo run -- --ip 8.8.8.8
```

You can also pass the ASN without the `AS` prefix:

```bash
cargo run -- --asn 15169
```

For IPinfo lookups, export a token first:

```bash
export IPINFO_TOKEN=your_token_here
cargo run -- --ip 8.8.8.8
IPinfo lookup for '8.8.8.8':
ASN: AS15169
Name: Google LLC
Domain: google.com
```

## Notes

- The `--company`, `--asn`, and `--google` flows rely on public third-party endpoints and page structure.
- The `--ip` flow uses IPinfo and falls back from the Core lookup endpoint to the Lite endpoint when the token does not have Core access.
- Deterministic unit tests cover local parsing logic, but some tests and runtime commands still depend on live network access.

## Project Structure

- `src/cli.rs`: CLI argument parsing with `clap`
- `src/main.rs`: command dispatch and terminal output
- `src/ipranges.rs`: HTTP requests, scraping, IP range aggregation, and IPinfo lookup logic

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
