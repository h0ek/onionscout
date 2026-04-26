# onionscout

![onionscout](https://raw.githubusercontent.com/h0ek/onionscout/refs/heads/main/onionscout.webp)

**onionscout** is a lightweight CLI tool for auditing Tor hidden services (`.onion`) for common security misconfigurations, clearnet dependencies, metadata leaks, fingerprinting indicators, and basic de-anonymization risks.

It is designed as a first-pass audit helper, not a full penetration-testing framework.

> Use only against systems you own or are authorized to assess.

## Features

### Network and origin handling

- Tor SOCKS5h support
- smart HTTP/HTTPS origin selection
- `.onion`-safe redirect policy
- redirect leak detection to clearnet
- retry handling for common onion/Tor network errors
- separate HTTP, SSH, and TLS timeouts

### Web fingerprinting

- web server header detection
- default error-page fingerprinting
- favicon discovery and Shodan-compatible favicon hash
- ETag extraction and Shodan query helper
- TLS reachability, TLS version, cipher, certificate SHA256, issuer, subject, and validity

### Leak and de-anonymization checks

- clearnet redirects
- external active resources
- external links
- CSP / CSP-Report-Only external allowances
- Report-To / NEL / Link header leakage
- canonical / alternate / OpenGraph / Twitter metadata leaks
- protocol-relative external links
- meta-refresh redirects
- clearnet form actions
- clearnet WebSocket endpoints
- Onion-Location header
- proxy-related headers
- common fingerprinting headers

### Hidden-service hygiene checks

- Apache `mod_status`
- Apache `mod_info`
- nginx `stub_status`
- WebDAV exposure
- common sensitive files and paths
- `.well-known/*` endpoints
- `robots.txt`
- `sitemap.xml`
- `security.txt` at root and `.well-known`
- CAPTCHA-related external resource leakage
- Set-Cookie attributes:
  - Secure
  - HttpOnly
  - SameSite
  - Domain

### Content indicators

- minimal same-host crawler
- email extraction
- obfuscated email extraction, for example `name(at)domain(dot)tld`
- placeholder email separation, for example `example.com`
- BTC / ETH / XMR address indicators
- HTML comments review
- comment-based IP, URL, JWT, private key, and secret-candidate detection

### Output

- human-readable Rich table
- JSON output for automation
- optional report file export

## Requirements

- Python 3.10+
- Tor SOCKS proxy:
  - Tor daemon: `127.0.0.1:9050`
  - Tor Browser: `127.0.0.1:9150`
  - Whonix Gateway example: `10.152.152.10:9050`

## Installation

### From PyPI

```bash
pipx install onionscout
```
### From GitHub

```
pipx install git+https://github.com/h0ek/onionscout.git
```

For local development:

```
git clone https://github.com/h0ek/onionscout.git
cd onionscout
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .
python3 onionscout.py -u <ONION_URL> --skip-tor-check
```

## Usage

```
onionscout -u <ONION_URL>
```

Example:

```
onionscout -u http://exampleonionaddress.onion --skip-tor-check
```

Use Tor Browser SOCKS:

```
onionscout -u http://exampleonionaddress.onion --socks 127.0.0.1:9150 --skip-tor-check
```

Force HTTP:

```
onionscout -u exampleonionaddress.onion --scheme http
```

Force HTTPS:

```
onionscout -u exampleonionaddress.onion --scheme https --insecure-https
```

Save TXT report:

```
onionscout -u exampleonionaddress.onion -o report.txt
```

Save JSON report:

```
onionscout -u exampleonionaddress.onion --json -o report.json
```

Disable crawler:

```
onionscout -u exampleonionaddress.onion --no-crawl
```

Tune crawler:

```
onionscout -u exampleonionaddress.onion --max-urls 150 --depth 2
```

Tune timeouts:

```
onionscout -u exampleonionaddress.onion --http-timeout 20 --ssh-timeout 8 --tls-timeout 12
```

## Options

```
-u, --url              Target .onion URL
--scheme              Origin scheme mode: auto, http, https
--socks               SOCKS5h proxy, default 127.0.0.1:9050
--skip-tor-check      Skip check.torproject.org connectivity check
--http-timeout        HTTP timeout
--ssh-timeout         SSH timeout
--tls-timeout         TLS timeout
--ssh-port            SSH port for fingerprint check
--retries             Retries for transient onion/Tor errors
--cookie              Raw Cookie header
--insecure-https      Disable HTTPS certificate verification for HTTP requests
--no-crawl            Disable crawler-based checks
--max-urls            Crawler URL limit
--depth               Crawler depth
--json                Output JSON
-o, --output          Save report to file
```

## Notes

- Most onion services use plain HTTP internally; HTTPS is supported when present.
- In `auto` mode, onionscout tests available origins and chooses a working HTTP or HTTPS origin.
- Redirects are followed only when they stay on `.onion`; clearnet redirects are reported as leaks.
- Some findings are context-dependent. For example, public social links may be intentional, while active clearnet scripts are usually more relevant for anonymity risk.
