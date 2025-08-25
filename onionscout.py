#!/usr/bin/env python3

import sys
import re
import time
import json
import argparse
import socket
import requests
import mmh3
import paramiko
import uuid
from io import BytesIO
from PIL import Image
from urllib.parse import urlparse, urljoin
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException
from paramiko import SSHException

try:
    import socks
except Exception:
    socks = None

from rich.console import Console
from rich.table import Table

ASCII_LOGO = r'''
 ▗▄▖ ▄▄▄▄  ▄  ▄▄▄  ▄▄▄▄       ▗▄▄▖▗▞▀▘ ▄▄▄  █  ▐▌   ■  
▐▌ ▐▌█   █ ▄ █   █ █   █     ▐▌   ▝▚▄▖█   █ ▀▄▄▞▘▗▄▟▙▄▖
▐▌ ▐▌█   █ █ ▀▄▄▄▀ █   █      ▝▀▚▖    ▀▄▄▄▀        ▐▌  
▝▚▄▞▘      █                 ▗▄▄▞▘                 ▐▌  
                                                   ▐▌  
v0.0.2
'''

console = Console()

class Config:
    def __init__(self, timeout: float, sleep: float, socks_host: str, socks_port: int):
        self.timeout = timeout
        self.sleep = sleep
        self.socks_host = socks_host
        self.socks_port = socks_port

cfg = Config(timeout=10.0, sleep=3.0, socks_host="127.0.0.1", socks_port=9050)

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
})
retry = Retry(
    total=5,
    backoff_factor=0.5,
    status_forcelist=[502, 503, 504],
    allowed_methods=["GET", "HEAD", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)

def configure_tor_proxy(host: str, port: int):
    proxy = f"socks5h://{host}:{port}"
    session.proxies = {"http": proxy, "https": proxy}

def get(url, **kwargs):
    timeout = kwargs.pop('timeout', cfg.timeout)
    return session.get(url, timeout=timeout, **kwargs)

def head(url, **kwargs):
    timeout = kwargs.pop('timeout', cfg.timeout)
    return session.head(url, timeout=timeout, **kwargs)

def options(url, **kwargs):
    timeout = kwargs.pop('timeout', cfg.timeout)
    return session.options(url, timeout=timeout, **kwargs)

def show_help():
    console.print(ASCII_LOGO)
    print_help_body()

def print_help_body():
    console.print("Lightweight CLI for basic Tor hidden-service (.onion) security checks\n")
    console.print("usage:")
    console.print("  onionscout [-t TIMEOUT] [-s SLEEP] [--socks HOST:PORT] [--skip-tor-check] [--json] -u URL\n")
    console.print("options:")
    console.print("  -t TIMEOUT           HTTP timeout in seconds (default: 10.0)")
    console.print("  -s SLEEP             seconds between checks (default: 3.0)")
    console.print("  --socks HOST:PORT    Tor SOCKS5h proxy (default: 127.0.0.1:9050)")
    console.print("  --ssh-port PORT      SSH port for fingerprint check (default: 22)")
    console.print("  --skip-tor-check     do not call check.torproject.org")
    console.print("  --json               output JSON instead of a table")
    console.print("  -u URL               .onion URL to scan (e.g. abcdef.onion)")

class CustomParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        super().__init__(add_help=False, **kwargs)

    def print_usage(self, file=None):
        pass

    def error(self, message):
        console.print(ASCII_LOGO)
        console.print(f"[red]Error: {message}[/red]\n")
        print_help_body()
        sys.exit(2)

def parse_socks(s: str):
    try:
        host, port = s.rsplit(":", 1)
        return host.strip(), int(port.strip())
    except Exception:
        raise ValueError("Invalid --socks value. Use HOST:PORT (e.g. 127.0.0.1:9050)")

def check_tor_proxy():
    try:
        r = get("http://check.torproject.org", timeout=5)
        return "Congratulations" in r.text
    except RequestException:
        return False

def shodan_favicon_hash(raw_content: bytes) -> int:
    img = Image.open(BytesIO(raw_content))
    frames = []
    try:
        for i in range(getattr(img, "n_frames", 1)):
            img.seek(i)
            frames.append(img.copy())
    except Exception:
        frames = [img]
    best = max(frames, key=lambda im: (im.width or 0) * (im.height or 0))
    try:
        resample = Image.Resampling.LANCZOS
    except AttributeError:
        resample = Image.LANCZOS
    thumb = best.resize((16, 16), resample=resample).convert("L")
    return mmh3.hash(thumb.tobytes(), signed=False)

def detect_server(url):
    try:
        out = []
        r = get(url)
        hdr = r.headers.get("Server", "")
        if hdr:
            out.append(f"Web server header: {hdr}")
        rand = uuid.uuid4().hex
        r404 = get(f"{url.rstrip('/')}/{rand}", allow_redirects=False)
        if r404.status_code == 404 and r404.text:
            m = re.search(r"(apache|nginx|lighttpd)(?:/([\d\.]+))?", r404.text.lower())
            if m:
                name = {"apache": "Apache", "nginx": "nginx", "lighttpd": "lighttpd"}[m.group(1)]
                ver = m.group(2) or ""
                out.append(f"Web server (error page): {name}{('/'+ver) if ver else ''}")
        return "\n".join(out) if out else "Web server not detected."
    except RequestException as e:
        return f"Error connecting (HTTP): {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

_REDIRECTS = {301, 302, 303, 307, 308}

def get_onion_follow(url, **kwargs):
    """
    GET without auto-redirects; follow a single redirect only if target host is .onion.
    Returns (response, leak_url). If leak_url is not None -> redirect to clearnet detected.
    """
    r = get(url, allow_redirects=False, **kwargs)
    if r.status_code in _REDIRECTS:
        loc = r.headers.get("Location")
        if not loc:
            return r, None
        nxt = urljoin(url, loc)
        host = (urlparse(nxt).hostname or "").lower()
        if host.endswith(".onion"):
            r2 = get(nxt, allow_redirects=False, **kwargs)
            return r2, None
        else:
            return None, nxt
    return r, None

ICON_LINK_RE = re.compile(
    r'<link\s+[^>]*rel=["\']([^"\']*icon[^"\']*)["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE
)

def detect_favicon(url):
    ico = f"{url.rstrip('/')}/favicon.ico"
    try:
        r, leak = get_onion_follow(ico)
        if leak:
            return f"Favicon redirect leak → {leak}"
        if r and r.status_code == 200 and r.content:
            h = shodan_favicon_hash(r.content)
            return f"Favicon found at {ico}. Shodan hash - http.favicon.hash:{h}"
        return "No favicon at /favicon.ico"
    except Exception as e:
        return f"Error detecting favicon: {e}"

def detect_favicon_in_html(url):
    try:
        r = get(url)
        matches = ICON_LINK_RE.findall(r.text)
        if not matches:
            return "No favicon in HTML"
        seen = set()
        leaks = []
        for rel, href in matches:
            fav_url = urljoin(url, href)
            if fav_url in seen:
                continue
            seen.add(fav_url)
            rf, leak = get_onion_follow(fav_url)
            if leak:
                leaks.append(leak)
                continue
            if rf and rf.status_code == 200 and rf.content:
                h = shodan_favicon_hash(rf.content)
                return f"Favicon in HTML: {fav_url}. Shodan hash - http.favicon.hash:{h}"
        if leaks:
            return "Favicon HTML redirect leak(s):\n" + "\n".join(sorted(set(leaks)))
        return "No favicon in HTML"
    except Exception as e:
        return f"Unexpected error: {e}"

def _make_socks_socket(host: str, port: int, timeout: float):
    if not socks:
        raise RuntimeError("PySocks not installed; install requests[socks] or PySocks")
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, cfg.socks_host, cfg.socks_port, rdns=True)
    s.settimeout(timeout)
    s.connect((host, port))
    return s

def check_ssh_fingerprint(url, ssh_port: int = 22):
    host = urlparse(url).hostname or ""
    if not host:
        return "SSH: invalid host"
    try:
        sock = _make_socks_socket(host, ssh_port, cfg.timeout)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=host, port=ssh_port, username=None, password=None,
                  sock=sock, timeout=cfg.timeout, banner_timeout=cfg.timeout, auth_timeout=cfg.timeout)
        t = c.get_transport()
        if not t:
            return "SSH transport not established"
        key = t.get_remote_server_key()
        fp = key.get_fingerprint()
        hex_fp = ":".join(f"{b:02x}" for b in fp)
        c.close()
        return f"SSH Fingerprint: {hex_fp} ({key.get_name()})"
    except (SSHException, socket.error, RuntimeError) as e:
        return f"SSH error: {e}"
    except Exception as e:
        return f"Unexpected SSH error: {e}"

def check_comments(url):
    try:
        r = get(url)
        cs = re.findall(r"<!--([\s\S]*?)-->", r.text)
        if not cs:
            return "No comments in code"
        out = ["Comments in code:"]
        for c in cs:
            for l in c.splitlines():
                l = l.strip()
                if l:
                    out.append(l)
        return "\n".join(out)
    except Exception as e:
        return f"Error fetching page: {e}"

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _found_ip_leak(text: str) -> str:
    m = IPV4_RE.search(text or "")
    return f"; leaked IP: {m.group()}" if m else ""

NGINX_STUB_RE = re.compile(
    r"Active connections:\s*\d+.*?server accepts handled requests\s*\d+\s+\d+\s+\d+.*?Reading:\s*\d+\s+Writing:\s*\d+\s+Waiting:\s*\d+",
    re.IGNORECASE | re.DOTALL
)

def check_status_pages(url):
    results = []

    try:
        u = f"{url.rstrip('/')}/server-status?auto"
        r = get(u, allow_redirects=False)
        if r.status_code == 200 and ("Total Accesses" in r.text or "ServerUptimeSeconds" in r.text):
            results.append(f"/server-status?auto (Apache mod_status) OPEN{_found_ip_leak(r.text)}")
        elif r.status_code in (401, 403):
            results.append("/server-status?auto (Apache mod_status) protected")
    except RequestException:
        pass

    try:
        u = f"{url.rstrip('/')}/server-status"
        r = get(u, allow_redirects=False)
        if r.status_code == 200 and ("Apache Server Status" in r.text or "Scoreboard" in r.text):
            results.append(f"/server-status (Apache mod_status HTML) OPEN{_found_ip_leak(r.text)}")
        elif r.status_code in (401, 403):
            results.append("/server-status (Apache mod_status HTML) protected")
    except RequestException:
        pass

    try:
        u = f"{url.rstrip('/')}/server-info"
        r = get(u, allow_redirects=False)
        if r.status_code == 200 and ("Apache Server Information" in r.text or "Server Module" in r.text):
            results.append("/server-info (Apache mod_info) OPEN")
        elif r.status_code in (401, 403):
            results.append("/server-info (Apache mod_info) protected")
    except RequestException:
        pass

    try:
        u = f"{url.rstrip('/')}/status"
        r = get(u, allow_redirects=False)
        if r.status_code == 200 and NGINX_STUB_RE.search(r.text or ""):
            results.append("/status (nginx stub_status) OPEN")
        elif r.status_code in (401, 403):
            results.append("/status (nginx stub_status) protected")
    except RequestException:
        pass

    try:
        for path in ("/webdav", "/"):
            u = f"{url.rstrip('/')}{path}"
            r = options(u, allow_redirects=False)
            dav = r.headers.get("DAV") or r.headers.get("Dav")
            allow = r.headers.get("Allow", "")
            if dav or ("PROPFIND" in allow or "MKCOL" in allow):
                results.append(f"{path} (WebDAV) ENABLED (DAV={dav or 'n/a'}, Allow={allow})")
                break
    except RequestException:
        pass

    return "\n".join(results) if results else "No status pages fingerprinted"

def check_files_and_paths(url):
    items = ["info.php", ".git", ".svn", ".hg", ".env", ".DS_Store", "security.txt"]
    paths = ["backup", "admin", "secret"]
    found = []
    base = url.rstrip('/')
    for f in items + paths:
        try:
            r = get(f"{base}/{f}", allow_redirects=False)
            if r.status_code == 200:
                prefix = "File" if f in items else "Path"
                found.append(f"{prefix} found: /{f}")
        except RequestException:
            continue
    return "\n".join(found) if found else "No sensitive files or paths found"

def check_external_resources(url):
    try:
        r = get(url)
        links = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', r.text, re.IGNORECASE)
        ext = [l for l in sorted(set(links)) if not (urlparse(l).hostname or "").endswith(".onion")]
        return "External resources:\n" + "\n".join(ext) if ext else "No external resources detected"
    except Exception as e:
        return f"Error fetching resources: {e}"

def check_cors(url):
    try:
        r = get(url)
        ac = {k: v for k, v in r.headers.items() if k.lower().startswith("access-control-")}
        return "CORS headers:\n" + "\n".join(f"{k}: {v}" for k, v in ac.items()) if ac else "No CORS headers"
    except Exception as e:
        return f"Error fetching headers: {e}"

META_REFRESH_RE = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', re.IGNORECASE)
CONTENT_ATTR_RE = re.compile(r'content=["\']([^"\']+)["\']', re.IGNORECASE)

def check_meta_redirects(url):
    try:
        r = get(url)
        metas = META_REFRESH_RE.findall(r.text)
        out = []
        for m in metas:
            c = CONTENT_ATTR_RE.search(m)
            if c:
                content = c.group(1)
                parts = content.split(";", 1)
                if len(parts) == 2 and "url=" in parts[1].lower():
                    tgt = parts[1].split("=", 1)[1].strip()
                    if tgt.startswith(("http://", "https://")) and not (urlparse(tgt).hostname or "").endswith(".onion"):
                        out.append(tgt)
        return "Meta-refresh redirects:\n" + "\n".join(out) if out else "No meta-refresh to clearnet URLs"
    except Exception as e:
        return f"Error fetching meta tags: {e}"

def check_robots_sitemap(url):
    out, base = [], url.rstrip('/')

    try:
        r, leak = get_onion_follow(f"{base}/robots.txt")
        if leak:
            out.append(f"/robots.txt redirect leak → {leak}")
        elif r and r.status_code == 200 and r.text:
            lines = [l for l in r.text.splitlines()
                     if l.lower().startswith(("disallow:", "sitemap:"))]
            if lines:
                out.append(f"/robots.txt entries:\n" + "\n".join(lines))
    except RequestException:
        pass

    try:
        r, leak = get_onion_follow(f"{base}/sitemap.xml")
        if leak:
            out.append(f"/sitemap.xml redirect leak → {leak}")
        elif r and r.status_code == 200 and r.text:
            locs = re.findall(r"<loc>([^<]+)</loc>", r.text, re.IGNORECASE)
            if locs:
                out.append(f"/sitemap.xml locs:\n" + "\n".join(locs))
    except RequestException:
        pass

    return "\n\n".join(out) if out else "No robots.txt or sitemap.xml entries found"

def check_form_actions(url):
    try:
        r = get(url)
        acts = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        out = [a for a in sorted(set(acts))
               if a.startswith(("http://", "https://")) and not (urlparse(a).hostname or "").endswith(".onion")]
        return "Form actions to clearnet:\n" + "\n".join(out) if out else "No clearnet form actions"
    except Exception as e:
        return f"Error fetching forms: {e}"

def check_websocket_endpoints(url):
    try:
        r = get(url)
        wss = re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', r.text, re.IGNORECASE)
        out = [ws for ws in sorted(set(wss)) if not (urlparse(ws).hostname or "").endswith(".onion")]
        return "WebSocket endpoints to clearnet:\n" + "\n".join(out) if out else "No clearnet WebSocket endpoints"
    except Exception as e:
        return f"Error fetching WebSocket endpoints: {e}"

def check_proxy_headers(url):
    try:
        r = get(url)
        keys = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded"]
        found = [f"{k}: {r.headers[k]}" for k in keys if k in r.headers]
        return "\n".join(found) if found else "No proxy-related headers"
    except Exception as e:
        return f"Error fetching proxy headers: {e}"

def check_security_txt(url):
    try:
        r = get(f"{url.rstrip('/')}/.well-known/security.txt", allow_redirects=False)
        return "security.txt:\n" + r.text.strip() if r.status_code == 200 else "security.txt not found"
    except Exception as e:
        return f"Error fetching security.txt: {e}"

def check_captcha_leak(url):
    try:
        r = get(url)
        if r.status_code != 200 or not r.text:
            return "No page to check for CAPTCHA leaks"
        text = r.text.lower()
        leaks = set(re.findall(
            r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, re.IGNORECASE))
        for path in ("/lua/cap.lua", "/queue.html"):
            if path in text:
                for m in re.findall(r'["\']([^"\']+' + re.escape(path) + r')["\']', text):
                    full = m if m.startswith("http") else f"{url.rstrip('/')}{m}"
                    leaks.add(full)
        real = [u for u in sorted(leaks) if not (urlparse(u).hostname or "").endswith(".onion")]
        return "Possible CAPTCHA leaks:\n" + "\n".join(real) if real else "No external CAPTCHA resources detected"
    except Exception as e:
        return f"Error fetching page: {e}"

def check_etag(url):
    """ETag header value (HEAD -> GET fallback) + Shodan dork."""
    try:
        r = head(url, allow_redirects=False)
        etag = r.headers.get("ETag") or r.headers.get("Etag")
        if not etag:
            r = get(url, allow_redirects=False)
            etag = r.headers.get("ETag") or r.headers.get("Etag")
        if etag:
            etag_clean = etag.strip().strip('"').strip("'")
            return f'ETag: "{etag_clean}" | Shodan: http.headers.etag:"{etag_clean}"'
        return "No ETag header"
    except Exception as e:
        return f"Error fetching ETag: {e}"

def main():
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = CustomParser(
        description="Lightweight CLI for basic Tor hidden-service (.onion) security checks"
    )
    parser.add_argument("-t", "--timeout", type=float, default=10.0,
                        help="HTTP timeout in seconds (default: 10.0)")
    parser.add_argument("-s", "--sleep", type=float, default=3.0,
                        help="Seconds between checks (default: 3.0)")
    parser.add_argument("--socks", default="127.0.0.1:9050",
                        help="Tor SOCKS5h proxy (default: 127.0.0.1:9050)")
    parser.add_argument("--ssh-port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--skip-tor-check", action="store_true",
                        help="Do not call check.torproject.org")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON report")
    parser.add_argument("-u", "--url", required=True,
                        help=".onion URL to scan (e.g. abcdef.onion)")
    args = parser.parse_args()

    cfg.timeout = args.timeout
    cfg.sleep   = args.sleep
    socks_host, socks_port = parse_socks(args.socks)
    cfg.socks_host, cfg.socks_port = socks_host, socks_port
    configure_tor_proxy(socks_host, socks_port)

    raw = args.url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    dom = p.netloc.lower()
    if not dom.endswith(".onion"):
        console.print(ASCII_LOGO)
        console.print("[red]Error: Provide a valid .onion URL[/red]\n")
        show_help()
        sys.exit(1)
    base_url = f"{p.scheme}://{p.netloc}"

    if not args.skip_tor_check and not check_tor_proxy():
        console.print(ASCII_LOGO)
        console.print("[yellow]Tor exit check failed (this may be expected). "
                      "Use --skip-tor-check for hidden services.[/yellow]\n")

    if not args.json:
        console.print(ASCII_LOGO)

    tasks = [
        ("Check Tor proxy",     lambda: "OK (skipped)" if args.skip_tor_check else "OK/Maybe (see note above)"),
        ("Detect server",       lambda: detect_server(base_url)),
        ("Detect favicon",      lambda: detect_favicon(base_url)),
        ("Favicon in HTML",     lambda: detect_favicon_in_html(base_url)),
        ("ETag header",         lambda: check_etag(base_url)),
        ("SSH fingerprint",     lambda: check_ssh_fingerprint(base_url, args.ssh_port)),
        ("Comments in code",    lambda: check_comments(base_url)),
        ("Status pages",        lambda: check_status_pages(base_url)),
        ("Files & paths",       lambda: check_files_and_paths(base_url)),
        ("External resources",  lambda: check_external_resources(base_url)),
        ("CORS headers",        lambda: check_cors(base_url)),
        ("Meta-refresh",        lambda: check_meta_redirects(base_url)),
        ("Robots & sitemap",    lambda: check_robots_sitemap(base_url)),
        ("Form actions",        lambda: check_form_actions(base_url)),
        ("WebSocket endpoints", lambda: check_websocket_endpoints(base_url)),
        ("Proxy headers",       lambda: check_proxy_headers(base_url)),
        ("security.txt",        lambda: check_security_txt(base_url)),
        ("CAPTCHA leak",        lambda: check_captcha_leak(base_url)),
    ]
    total = len(tasks)
    results = []

    for idx, (desc, fn) in enumerate(tasks, start=1):
        if not args.json:
            with console.status(f"{idx}/{total} {desc}: in progress"):
                out = fn()
                time.sleep(cfg.sleep)
            console.print(f"[green]{idx}/{total} {desc}: done[/green]")
        else:
            out = fn()
        results.append((desc, out))

    if args.json:
        print(json.dumps({k: v for k, v in results}, ensure_ascii=False, indent=2))
        return

    console.print("\n[bold green]All steps complete[/bold green]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="bold")
    table.add_column("Result")
    for desc, out in results:
        table.add_row(desc, (out or "").replace("\n", " | "))
    console.print(table)

if __name__ == "__main__":
    main()
