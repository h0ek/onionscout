# onionscout

![onionscout](onionscout.webp)

**onionscout** is a lightweight CLI for basic security-checks of Tor hidden services (.onion).

> **Disclaimer:**  
> This is *not* a full-blown pentesting or “super-hacker” tool. It’s a simple, low-hanging-fruit scanner designed to help you quickly spot common misconfigurations and basic information leaks on a Tor hidden service. Use it as a first pass, not a replacement for a thorough security audit.

## Checks

1. **Check Tor proxy**  
   - Calls `get("http://check.torproject.org", timeout=5)` via the shared `session` configured with `socks5h://127.0.0.1:9050`.  
   - Uses `requests`’ retry logic (5 attempts, exponential backoff) and a 5 s override timeout.  
   - Returns `True` if the HTML response contains `"Congratulations"` (working Tor exit).  
   - Note: hidden services don’t need an exit; you can skip this with `--skip-tor-check`.  

2. **Detect server**  
   - `get(url)` fetches the homepage and inspects `r.headers.get("Server")`.  
   - Generates a random UUID path and requests `GET {url}/{UUID}` **with redirects disabled**.  
   - If it returns 404, inspects the body via `re.search(r"(apache|nginx|lighttpd)(?:/([\d\.]+))?")` to infer server type/version from default error pages.  

3. **Detect favicon**  
   - Requests `/favicon.ico` using **controlled redirects**: follow at most one redirect **only if** the target host ends with `.onion`; a redirect to clearnet is reported as `Favicon redirect leak → <url>`.  
   - Loads bytes into a Pillow `Image`, iterates ICO frames (`img.n_frames`), picks the largest (width×height).  
   - Resizes to 16×16 (Lanczos), converts to 8-bit grayscale (`convert("L")`), hashes with MurmurHash3 (`mmh3.hash(..., signed=False)`).  
   - Prints a Shodan dork: `http.favicon.hash:<hash>`.  

4. **Favicon in HTML**  
   - Fetches the homepage, locates `<link rel="...icon..." href="...">` via  
     `r'<link\s+[^>]*rel=["\']([^"\']*icon[^"\']*)["\'][^>]*href=["\']([^"\']+)'`.  
   - Resolves relative URLs and fetches using the same **controlled redirect** policy as in step 3 (clearnet redirects reported as `Favicon HTML redirect leak(s)`).  
   - Hashing identical to step 3.  

5. **ETag header**  
   - Attempts `HEAD` first (no redirects), then `GET` fallback.  
   - If `ETag` present, normalizes quotes and prints value plus Shodan dork: `http.headers.etag:"<value>"`.  

6. **SSH fingerprint**  
   - Parses hostname from `urlparse(url).hostname`.  
   - Connects via Paramiko **through Tor** by injecting a SOCKS5 socket (PySocks) with `rdns=True` (DNS for `.onion` resolved inside Tor).  
   - Obtains server key via `get_remote_server_key().get_fingerprint()`, formats as colon-separated hex and includes key type (e.g., `ssh-ed25519`).  
   - Default port 22; override with `--ssh-port`. Connection refused simply means SSH isn’t exposed.  

7. **Comments in code**  
   - Downloads HTML; finds `<!-- … -->` blocks with `re.findall(r"<!--([\s\S]*?)-->", r.text)`.  
   - Splits each comment on newlines and trims whitespace to surface notes/tokens.  

8. **Status pages**  
   - Probes with redirects disabled:  
     - Apache **mod_status**: `/server-status?auto` (looks for `Total Accesses`, `ServerUptimeSeconds`, `Scoreboard`) and `/server-status` (HTML “Apache Server Status”/`Scoreboard`).  
     - Apache **mod_info**: `/server-info` (texts like “Apache Server Information”, “Server Module”).  
     - **nginx stub_status**: `/status` (plaintext pattern with `Active connections:` and `Reading:/Writing:/Waiting:`).  
     - **WebDAV**: `OPTIONS` on `/webdav` then `/`; presence of `DAV` header or `Allow` containing `PROPFIND`/`MKCOL`.  
   - If accessible, reports `OPEN`/`protected`; scans body for IPv4 leakage with `r"\b(?:\d{1,3}\.){3}\d{1,3}\b"` and appends `; leaked IP: <ip>`.  

9. **Files & paths**  
   - Checks common sensitive files (`info.php`, `.git`, `.svn`, `.hg`, `.env`, `.DS_Store`, `security.txt`, etc.) and directories (`admin`, `backup`, `secret`).  
   - For each entry, issues `GET {url}/{entry}` **with redirects disabled**; reports any that return HTTP 200.  

10. **External resources**  
    - Parses the homepage with `re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', r.text, flags=IGNORECASE)`.  
    - Filters out URLs whose hostname ends with `.onion`, listing any clearnet dependencies (JS, CSS, images).  

11. **CORS headers**  
    - After `get(url)`, iterates `r.headers.items()`, selects any keys starting with `Access-Control-`.  
    - Prints each `header: value` or “No CORS headers” if none found.  

12. **Meta-refresh**  
    - Finds `<meta http-equiv="refresh" ...>` tags via `re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', r.text, flags=IGNORECASE)`.  
    - Extracts the `content="…url=TARGET"` portion; if `TARGET` begins with `http://` or `https://` and isn’t `.onion`, reports it as a clearnet redirect.  

13. **Robots & sitemap**  
    - Requests `/robots.txt` and `/sitemap.xml` using **controlled redirects**: follow one hop only if the redirect stays within `.onion`; clearnet redirects are reported as `/<file> redirect leak → <url>`.  
    - For `robots.txt`, extracts lines starting with `Disallow:` or `Sitemap:`.  
    - For `sitemap.xml`, extracts all URLs inside `<loc>…</loc>`.  

14. **Form actions**  
    - Searches HTML for `<form ... action="…">` with `re.findall`.  
    - Reports any actions pointing to non-`.onion` hosts (i.e., `action="http://..."`), which could leak form data.  

15. **WebSocket endpoints**  
    - Uses `re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', r.text, flags=IGNORECASE)` to detect JavaScript WS/WSS connections.  
    - Filters out any whose hostname ends with `.onion`, exposing clearnet sockets.  

16. **Proxy headers**  
    - Checks response headers for `X-Forwarded-For`, `X-Real-IP`, `Via`, `Forwarded`.  
    - Prints their values if present (may reveal upstream/client info) or “No proxy-related headers”.  

17. **security.txt**  
    - `GET /.well-known/security.txt` (redirects disabled); on HTTP 200 prints its full contents, revealing security contacts or disclosures.  

18. **CAPTCHA leak**  
    - Lowers page text and finds all URLs containing `captcha` via  
      `re.findall(r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, flags=IGNORECASE)`.  
    - Additionally searches for `/lua/cap.lua` and `/queue.html`, resolves relative paths, and filters out `.onion` hosts — exposing external CAPTCHA services.  

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
onionscout
```

Run a scan
```bash
onionscout -u <ONION_URL>
```
### Examples
```bash
# Standard scan (Tor daemon on 9050)
onionscout -u <ONION_URL> --skip-tor-check --socks 127.0.0.1:9050

# Using Tor Browser SOCKS (usually 9150)
onionscout -u <ONION_URL> --skip-tor-check --socks 127.0.0.1:9150

# Increase HTTP timeout and slow down between checks
onionscout -u <ONION_URL> -t 20 -s 5

# Specify custom SSH port for fingerprinting
onionscout -u <ONION_URL> --ssh-port 2222

# Machine-readable output
onionscout -u <ONION_URL> --json
```

## Command-line Options

The script accepts the following parameters:

`-u, --url <onion_url>`  
**Required.** The target .onion address to scan (e.g., `abcdef1234567890.onion`).

`-t, --timeout <seconds>`  
**Optional.** HTTP request timeout in seconds.  
**Default:** `10.0`

`-s, --sleep <seconds>`  
**Optional.** Delay between each check, in seconds.  
**Default:** `3.0`

`--socks <HOST:PORT>`  
**Optional.** Tor SOCKS5h proxy (remote DNS) used for all HTTP(S) checks and SSH via SOCKS.  
**Default:** `127.0.0.1:9050`  
*(Tor Browser is typically `127.0.0.1:9150`.)*

`--ssh-port <port>`  
**Optional.** SSH port used by the SSH fingerprint check.  
**Default:** `22`

`--skip-tor-check`  
**Optional.** Skip calling `check.torproject.org`.  

`--json`  
**Optional.** Print the final report as JSON (useful for automation).

## Uninstall
```bash
pipx uninstall onionscout
```

## Update
```bash
pipx upgrade onionscout
```

## ToDo
- [x] Add Etag search (Shodan example: http.headers.etag:"5f6a3b7e2c1d4")
- [x] Remove false positives for status pages
