# onionscout

![onionscout](onionscout.webp)

**onionscout** is a lightweight CLI for basic security-checks of Tor hidden services (.onion).

It will perform checks such as:
1. **Check Tor proxy**  
   - Calls `get("http://check.torproject.org", timeout=5)` via the shared `session` configured with `socks5h://127.0.0.1:9050`.  
   - Uses `requests`’ retry logic (5 attempts, exponential backoff) and a 5 s override timeout.  
   - Returns `True` if the HTML response contains the string `"Congratulations"`, indicating a working Tor exit.

2. **Detect server**  
   - `get(url)` fetches the homepage and inspects `r.headers.get("Server")`.  
   - Generates a random UUID path and requests `GET url/UUID`. If it returns 404, inspects the body via `re.search(r"(apache|nginx|lighttpd)(?:/([\d\.]+))?")` to infer server type and version from default error pages.

3. **Detect favicon**  
   - Downloads `/favicon.ico` with `get()`.  
   - Loads the raw bytes into a PIL `Image`, iterates all ICO frames (`img.n_frames`), picks the one with the largest width×height.  
   - Resizes to 16×16 using Lanczos, converts to 8-bit grayscale (`convert("L")`), and hashes the pixel buffer with MurmurHash3 (`mmh3.hash(..., signed=False)`).

4. **Favicon in HTML**  
   - Fetches the homepage HTML, applies regex `r'<link\s+[^>]*rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)'` to locate any `<link rel=...icon href=...>` tag.  
   - Resolves relative URLs via `urljoin`, re-downloads that file, and hashes it exactly as in step 3.

5. **SSH fingerprint**  
   - Parses the hostname from `urlparse(url).hostname`.  
   - Uses Paramiko’s `SSHClient`, connects to port 22 with a 10 s timeout and `AutoAddPolicy()`.  
   - Calls `get_remote_server_key().get_fingerprint()`, formats the byte fingerprint into colon-separated hex.

6. **Comments in code**  
   - Downloads the page HTML, finds all `<!-- … -->` blocks with `re.findall(r"<!--([\s\S]*?)-->", r.text)`.  
   - Splits each comment on newlines and trims whitespace, collecting any developer notes or hidden tokens.

7. **Status pages**  
   - Iterates known endpoints: `/server-status`, `/server-info`, `/status`, `/webdav`.  
   - For each, issues `get(url + path)`. If `r.status_code` is 200, 401 or 403, notes accessibility.  
   - Uses `re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")` on the body to detect any raw IPv4 leakage.

8. **Files & paths**  
   - Checks common sensitive items: files (`info.php`, `.git`, `.env`, `security.txt`, etc.) and directories (`admin`, `backup`, `secret`).  
   - For each entry, does `get(url + "/" + entry)`, reports any that return HTTP 200.

9. **External resources**  
   - Parses the homepage with `re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']')`.  
   - Filters out URLs whose hostname ends with `.onion`, listing any clearnet dependencies (JS, CSS, images).

10. **CORS headers**  
    - After `get(url)`, iterates `r.headers.items()`, selects any keys starting with `Access-Control-`.  
    - Prints each header:value or “No CORS headers” if none found.

11. **Meta-refresh**  
    - Finds `<meta http-equiv="refresh" ...>` tags via `re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', ...)`.  
    - Extracts the `content="…url=TARGET"` portion, and if `TARGET` begins with `http://` or `https://`, reports it as a clearnet redirect.

12. **Robots & sitemap**  
    - Fetches `/robots.txt`, filters lines that start with `Disallow:` or `Sitemap:`.  
    - Fetches `/sitemap.xml`, extracts all URLs inside `<loc>…</loc>` tags via `re.findall`.

13. **Form actions**  
    - Searches HTML for `<form ... action="…">` with `re.findall`.  
    - Reports any actions pointing to non-`.onion` hosts (i.e. `action="http://..."`), which could leak form data.

14. **WebSocket endpoints**  
    - Uses regex `re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', ...)` to detect JavaScript WS/WSS connections.  
    - Filters out any whose hostname ends with `.onion`, exposing clearnet sockets.

15. **Proxy headers**  
    - Checks response headers for `X-Forwarded-For`, `X-Real-IP`, `Via`, `Forwarded`.  
    - Prints their values if present, indicating backend may reveal client IP.

16. **security.txt**  
    - GETs `/.well-known/security.txt`; on HTTP 200 prints its full contents, revealing security contacts or disclosures.

17. **CAPTCHA leak**  
    - Lowers the page text and finds all URLs containing `captcha` via `re.findall(r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)')`.  
    - Additionally searches for `/lua/cap.lua` and `/queue.html` occurrences, resolves relative paths to full URLs, and filters out `.onion` hosts — exposing external CAPTCHA services.

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
