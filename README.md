# RDAP Stealth Finder

A Go tool that discovers RDAP (Registration Data Access Protocol) servers that are not publicly advertised in the IANA bootstrap files.

## Introduction

RDAP (Registration Data Access Protocol) is a protocol that replaces WHOIS for accessing domain name registration data. RDAP servers are typically listed in bootstrap files provided by IANA, but some TLD operators run "stealth" RDAP servers that are not listed in these bootstrap files.

This tool attempts to discover these stealth RDAP servers by:

1. Downloading the list of all TLDs from IANA
2. Downloading the list of known RDAP servers from the IANA bootstrap file
3. For each TLD without a known RDAP server, attempting to discover a stealth RDAP server using common patterns

## Installation

### Prerequisites

- Go 1.24.0 or later

### Installing from source

```bash
git clone https://github.com/kriztalz/rdap-stealth-finder.git
cd rdap-stealth-finder
go build ./cmd/rdap-stealth-finder
```

## Usage

Basic usage to check all TLDs:

```bash
./rdap-stealth-finder
```

Check a single TLD:

```bash
./rdap-stealth-finder --tld li
```

With options:

```bash
./rdap-stealth-finder -c 20 -t 15 -v
```

Combine single TLD check with other options:

```bash
./rdap-stealth-finder --tld li -v
```

### Options

- `--tld`: Check a specific TLD (e.g., 'ch', 'co', or 'in')
- `-c, --concurrency`: Number of concurrent workers (default: 10)
- `-t, --timeout`: HTTP request timeout in seconds (default: 10)
- `-v, --verbose`: Enable verbose logging

## How It Works

The tool follows these steps:

When checking all TLDs:
1. Fetches the list of all TLDs from `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`
2. Fetches the RDAP bootstrap file from `https://data.iana.org/rdap/dns.json`
3. Identifies TLDs that don't have a published RDAP server in the bootstrap file
4. For each of these TLDs, attempts to discover a stealth RDAP server

When checking a single TLD:
1. First checks if the TLD has a known RDAP server in the bootstrap file
2. If not found in the bootstrap file, attempts to discover a stealth RDAP server by:
   - Querying the IANA RDAP server for information about the TLD
   - Extracting the `port43` field (typically containing a WHOIS server address)
   - Constructing potential RDAP server URLs based on common patterns
   - Testing each URL to see if it's a valid RDAP server

## Example Output

Checking all TLDs:
```
=== RDAP Server Discovery Summary ===
Total TLDs: 1443
Published RDAP servers: 1188
Stealth RDAP servers: 33
Unknown RDAP servers: 222

=== Stealth RDAP Servers Found ===
CL:
  Host: nic.cl
  Endpoint: https://nic.cl/rdap/
NG:
  Host: rdap.nic.net.ng
  Endpoint: https://rdap.nic.net.ng/domain/
XN--H2BREG3EVE:
  Host: rdap.registry.in
  Endpoint: https://rdap.registry.in/domain/
XN--H2BRJ9C:
  Host: rdap.registry.in
  Endpoint: https://rdap.registry.in/domain/
```

Checking a single TLD (in bootstrap file):
```
Found published RDAP server(s) for COM:
- Host: rdap.verisign.com
  Endpoint: https://rdap.verisign.com/com/v1/
```

Checking a single TLD (stealth server):
```
Found stealth RDAP server for LI:
- Host: rdap.nic.li
  Endpoint: https://rdap.nic.li/domain/
```

Checking a single TLD (no RDAP server):
```
No RDAP server found for XYZ
```

## Features

- **Concurrent Processing**: Utilizes multiple workers to efficiently check many TLDs
- **Robust Error Handling**: Properly handles connection failures and timeouts
- **Smart URL Construction**: Tries multiple URL patterns based on common conventions
- **Structured Logging**: Uses Go's `slog` package for structured JSON logging
- **Single TLD Mode**: Supports checking individual TLDs for quick lookups

## Security Considerations

Please use this tool responsibly. Respect rate limits and be mindful that:

1. Attempting to access RDAP servers may be subject to terms of service
2. Some operators may consider excessive querying as abusive behavior
3. Always identify yourself properly in HTTP requests

## License

MIT License 