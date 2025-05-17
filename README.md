# onionscout

![onionscout](onionscout.webp)

**onionscout** is a lightweight CLI for basic security-checks of Tor hidden services (.onion).

It will perform checks such as:
01. Check Tor proxy: Verifies that the local Tor SOCKS proxy is running and functional.
02. Detect server: Sends an HTTP request, reads the Server header or error page text, and reports Apache, Nginx, Lighttpd, or “not detected.”
03. Detect favicon: Fetches /favicon.ico, resizes it to 16×16, converts to grayscale, and computes an unsigned MurmurHash3.
04. Favicon in HTML: Parses <link rel="…icon"> tags in the page, fetches that file, and computes the same Shodan–style hash.
05. SSH fingerprint: Opens an SSH connection to port 22, retrieves the server’s public-key fingerprint, and prints it in hex.
06. Comments in code: Scans the HTML for <!-- ... --> blocks and lists any inline comments.
07. Status pages: Probes common status endpoints (/server-status, /status, etc.), notes which are accessible, and flags any leaked IPv4 addresses.
08. Files & paths: Checks for sensitive files (.git, .env, security.txt, etc.) and directories (/admin, /backup, /secret).
09. External resources: Extracts all src/href URLs, filters out .onion hosts, and lists any clearnet assets.
10. CORS headers: Reads the Access-Control-Allow-Origin header and reports its value (or absence).
11. Meta-refresh: Finds <meta http-equiv="refresh"> tags that redirect to clearnet URLs.
12. Robots & sitemap: Fetches /robots.txt and /sitemap.xml, then prints any Disallow: or Sitemap: lines and <loc> entries.
13. Form actions: Looks for <form action="…"> attributes pointing to clearnet hosts.
14. WebSocket endpoints: Searches for new WebSocket("ws://…") calls that connect to non-onion hosts.
15. Proxy headers: Checks response headers (X-Forwarded-For, X-Real-IP, Via, Forwarded) and shows any values.
16. security.txt: Fetches /.well-known/security.txt and prints its contents if found.
17. CAPTCHA leak: Scans page text for external CAPTCHA URLs or scripts (e.g. /lua/cap.lua) and lists any clearnet references.

## Requirements

- Python 3.8+  
- Tor listening on `127.0.0.1:9050`
- **pipx** (recommended)

## Installation via pipx

**Install pipx** (if you haven’t already):  
```bash
python3 -m pip install --user pipx
pipx ensurepath
```

**Install onionscout**
```bash
pipx install git+https://github.com/h0ek/onionscout.git
```

## Usage

Show help
```bash
onionscout -h
```

Run a scan at Whonix Workstation
```bash
onionscout -u <ONION_URL>
```

## Uninstall
```bash
pipx uninstall onionscout
```

## Update
```bash
pipx upgrade onionscout
```
