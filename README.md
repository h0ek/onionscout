# onionscout

![onionscout](onionscout.webp)

**onionscout** is a lightweight CLI for basic security-checks of Tor hidden services (.onion).

> **Disclaimer:**  
> This is *not* a full-blown pentesting or “super-hacker” tool. It’s a simple, low-hanging-fruit scanner designed to help you quickly spot common misconfigurations and basic information leaks on a Tor hidden service. Use it as a first pass, not a replacement for a thorough security audit.

## Checks

1. **SOCKS/Tor connectivity check**  
   - Calls `get("http://check.torproject.org", timeout=5)` via `session` configured with `socks5h://127.0.0.1:9050`.  
   - Returns pass/fail (or `Skipped (--skip-tor-check)` when disabled).

2. **Detect server**  
   - `get(url)` fetches the homepage and inspects `r.headers.get("Server")`.  
   - Generates a random UUID path and requests `GET {url}/{UUID}` **with redirects disabled**.  
   - If it returns 404, inspects the body via `re.search(r"(apache|nginx|lighttpd)(?:/([\d\.]+))?")` to infer server type/version from default error pages.
  
3. **HTTPS/TLS sanity**
   -  Probes `https://<onion>/` (port 443) via Tor SOCKS.
   -  If reachable, extracts basic TLS certificate metadata (Subject, Issuer, Validity, SAN).
   -  If not reachable, reports `HTTPS/TLS: not reachable`.

4. **Detect favicon**
   - Requests `/favicon.ico` using **controlled redirects**: follow at most one redirect **only if** the target host ends with `.onion`; a redirect to clearnet is reported as `Favicon redirect leak → <url>`.
   - Computes Shodan-compatible MurmurHash3 over the favicon bytes (same approach as Shodan/favscan conceptually: hash of the favicon “data”).
   - Prints a ready Shodan dork: `http.favicon.hash:<hash>`.
     
5. **Favicon in HTML**  
   - Fetches the homepage, locates `<link rel="...icon..." href="...">` via  
        `r'<link\s+[^>]*rel=["\']([^"\']*icon[^"\']*)["\'][^>]*href=["\']([^"\']+)'`.  
   - Resolves relative URLs and fetches using the same **controlled redirect** policy as in step 3 (clearnet redirects reported as `Favicon HTML redirect leak(s)`).  
   - Hashing identical to step 4 and prints `http.favicon.hash:<hash>` (Shodan dork).
 
6. **ETag header**  
   - Attempts `HEAD` first (no redirects), then `GET` fallback.  
   - If `ETag` present, normalizes quotes and prints value plus Shodan dork: `http.headers.etag:"<value>"`.  

7. **SSH fingerprint**  
   - Parses hostname from `urlparse(url).hostname`.  
   - Connects via Paramiko **through Tor** by injecting a SOCKS5 socket (PySocks) with `rdns=True` (DNS for `.onion` resolved inside Tor).  
   - Obtains server key via `get_remote_server_key().get_fingerprint()`, formats as colon-separated hex and includes key type (e.g., `ssh-ed25519`).  
   - Default port 22; override with `--ssh-port`. Connection refused simply means SSH isn’t exposed.
   - Uses `allow_agent=False` and `look_for_keys=False` to reduce auth noise; it only needs the host key. 

8. **Comments in code**  
   - Downloads HTML; finds `<!-- … -->` blocks with `re.findall(r"<!--([\s\S]*?)-->", r.text)`.  
   - Splits each comment on newlines and trims whitespace to surface notes/tokens.  

9. **Status pages**  
   - Probes with redirects disabled:  
      - Apache **mod_status**: `/server-status?auto` (looks for `Total Accesses`, `ServerUptimeSeconds`, `Scoreboard`) and `/server-status` (HTML “Apache Server Status”/`Scoreboard`).  
      - Apache **mod_info**: `/server-info` (texts like “Apache Server Information”, “Server Module”).  
      - **nginx stub_status**: `/status` (plaintext pattern with `Active connections:` and `Reading:/Writing:/Waiting:`).  
      - **WebDAV**: `OPTIONS` on `/webdav` then `/`; presence of `DAV` header or `Allow` containing `PROPFIND`/`MKCOL`.  
   - If accessible, reports OPEN/protected; scans body for valid IPv4 leakage and appends ; `leaked IP: <ip>`.  

10. **Files & paths**
   - Checks common sensitive files (`info.php`, `.git`, `.svn`, `.hg`, `.env`, `.DS_Store`, etc.) and directories (`admin`, `backup`, `secret`).
   - Uses redirects disabled.
   - Includes a **soft-404 / catch-all 200 filter**: it first fetches a random non-existent path as a baseline, then skips results that look like the same “default page/index” response (reduces false positives when the server returns 200 for everything).

11. **External resources**  
   - Parses the homepage with `re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', r.text, flags=IGNORECASE)`.  
   - Filters out URLs whose hostname ends with `.onion`, listing any clearnet dependencies (JS, CSS, images).  

12. **CORS headers**  
   - After `get(url)`, iterates `r.headers.items()`, selects any keys starting with `Access-Control-`.  
   - Prints each `header: value` or “No CORS headers” if none found.  

13. **Meta-refresh**  
   - Finds `<meta http-equiv="refresh" ...>` tags via `re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', r.text, flags=IGNORECASE)`.  
   - Extracts the `content="…url=TARGET"` portion; if `TARGET` begins with `http://` or `https://` and isn’t `.onion`, reports it as a clearnet redirect.  

14. **Robots & sitemap**  
   - Requests `/robots.txt` and `/sitemap.xml` using **controlled redirects**: follow one hop only if the redirect stays within `.onion`; clearnet redirects are reported as `/<file> redirect leak → <url>`.  
   - For `robots.txt`, extracts lines starting with `Disallow:` or `Sitemap:`.  
   - For `sitemap.xml`, extracts all URLs inside `<loc>…</loc>`.  

15. **Form actions**  
   - Searches HTML for `<form ... action="…">` with `re.findall`.  
   - Reports any actions pointing to non-`.onion` hosts (i.e., `action="http://..."`), which could leak form data.  

16. **WebSocket endpoints**  
   - Uses `re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', r.text, flags=IGNORECASE)` to detect JavaScript WS/WSS connections.  
   - Filters out any whose hostname ends with `.onion`, exposing clearnet sockets.  

17. **Proxy headers**  
   - Checks response headers for `X-Forwarded-For`, `X-Real-IP`, `Via`, `Forwarded`.  
   - Prints their values if present (may reveal upstream/client info) or “No proxy-related headers”.  

18. **CAPTCHA leak**  
   - Lowers page text and finds all URLs containing `captcha` via  
      `re.findall(r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, flags=IGNORECASE)`.  
   - Additionally searches for `/lua/cap.lua` and `/queue.html`, resolves relative paths, and filters out `.onion` hosts — exposing external CAPTCHA services.

19. **Onion-Location header**
   - Reports `Onion-Location` header if present.
   
20. **Header leaks**
   - Highlights common fingerprinting/leak headers (e.g., `Server`, `X-Powered-By`, `X-Generator`, etc.).
   
21. **Well-known endpoints**
   - Probes common `/.well-known/*` endpoints and reports those returning HTTP 200.
   
22. **Protocol-relative links**
   - Detects `src/href="//..."` dependencies and reports non-`.onion` hosts.

23. **security.txt (root)**
   - `GET /security.txt` (redirects disabled); prints contents on HTTP 200.

24. **security.txt (.well-known)**
   - `GET /.well-known/security.txt` (redirects disabled); prints contents on HTTP 200.

## Requirements
- Python 3.8+  
- Tor listening on `127.0.0.1:9050`; Tor Browser uses 9150 by default (use --socks 127.0.0.1:9150).”
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

# Save report to a file (TXT by default)
onionscout -u <ONION_URL> -o report.txt

# Save machine-readable JSON to a file
onionscout -u <ONION_URL> --json -o report.json
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

`-o, --output <path>`
**Optional.** Write the final report to a file.
   - If `--json` is set → writes JSON
   - Otherwise → writes a TXT report (human-readable)

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
- [x] Reduce false positives for file/path hits (soft-404 baseline)
- [x] Add HTTPS/TLS sanity check
- [x] Add Onion-Location + header leak checks
- [x] Add .well-known enumeration + protocol-relative dependency detection
- [x] Add report export to file (-o/--output)
