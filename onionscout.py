#!/usr/bin/env python3
import sys
import re
import time
import argparse
import requests
import mmh3
import paramiko
import uuid
from io import BytesIO
from PIL import Image
from urllib.parse import urlparse, urljoin
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from rich.console import Console
from rich.table import Table
from requests.exceptions import RequestException
from paramiko import SSHException

ASCII_LOGO = r'''
 ▗▄▖ ▄▄▄▄  ▄  ▄▄▄  ▄▄▄▄       ▗▄▄▖▗▞▀▘ ▄▄▄  █  ▐▌   ■  
▐▌ ▐▌█   █ ▄ █   █ █   █     ▐▌   ▝▚▄▖█   █ ▀▄▄▞▘▗▄▟▙▄▖
▐▌ ▐▌█   █ █ ▀▄▄▄▀ █   █      ▝▀▚▖    ▀▄▄▄▀        ▐▌  
▝▚▄▞▘      █                 ▗▄▄▞▘                 ▐▌  
                                                   ▐▌  
v0.0.1
'''

console = Console()

class Config:
    def __init__(self, timeout: float, sleep: float):
        self.timeout = timeout
        self.sleep = sleep

cfg = Config(timeout=10.0, sleep=3.0)

session = requests.Session()
session.proxies = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
                  "Gecko/20100101 Firefox/128.0"
})
retry = Retry(
    total=5,
    backoff_factor=0.5,
    status_forcelist=[502, 503, 504],
    allowed_methods=["GET"]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)

def get(url, **kwargs):
    timeout = kwargs.pop('timeout', cfg.timeout)
    return session.get(url, timeout=timeout, **kwargs)

def show_help():
    console.print(ASCII_LOGO)
    print_help_body()

def print_help_body():
    console.print("Lightweight CLI for basic Tor hidden-service (.onion) security checks\n")
    console.print("usage:")
    console.print("  onionscout [-t TIMEOUT] [-s SLEEP] -u URL\n")
    console.print("options:")
    console.print("  -t TIMEOUT       HTTP timeout in seconds (default: 10.0)")
    console.print("  -s SLEEP         seconds between checks (default: 3.0)")
    console.print("  -u URL           .onion URL to scan (e.g. abcdef.onion)")

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
        for i in range(img.n_frames):
            img.seek(i)
            frames.append(img.copy())
    except (AttributeError, EOFError):
        frames = [img]
    best = max(frames, key=lambda im: im.width * im.height)
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
        r404 = get(f"{url.rstrip('/')}/{rand}")
        if r404.status_code == 404:
            m = re.search(r"(apache|nginx|lighttpd)(?:/([\d\.]+))?", r404.text.lower())
            if m:
                name = m.group(1).capitalize()
                ver = m.group(2) or ""
                out.append(f"Web server (error page): {name}{('/'+ver) if ver else ''}")
        return "\n".join(out) or "Web server not detected."
    except RequestException as e:
        return f"Error connecting (HTTP): {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def detect_favicon(url):
    ico = f"{url.rstrip('/')}/favicon.ico"
    try:
        r = get(ico)
        if r.status_code == 200:
            h = shodan_favicon_hash(r.content)
            return f"Favicon found at {ico}. Shodan hash - http.favicon.hash:{h}"
        return "No favicon at /favicon.ico"
    except RequestException:
        return "No favicon at /favicon.ico"
    except Exception as e:
        return f"Error detecting favicon: {e}"

def detect_favicon_in_html(url):
    try:
        r = get(url)
        m = re.search(
            r'<link\s+[^>]*rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)["\']',
            r.text, re.IGNORECASE
        )
        if m:
            href = m.group(1)
            fav_url = urljoin(url, href)
            rf = get(fav_url)
            if rf.status_code == 200:
                h = shodan_favicon_hash(rf.content)
                return f"Favicon in HTML: {fav_url}. Shodan hash - http.favicon.hash:{h}"
        return "No favicon in HTML"
    except RequestException as e:
        return f"Error fetching HTML/favicon: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_ssh_fingerprint(url):
    host = urlparse(url).hostname or ""
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=22, username="", password="", timeout=10)
        fp = c.get_transport().get_remote_server_key().get_fingerprint()
        hex_fp = ":".join(f"{b:02x}" for b in fp)
        c.close()
        return f"SSH Fingerprint: {hex_fp}"
    except SSHException as e:
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
                out.append(l.strip())
        return "\n".join(out)
    except RequestException as e:
        return f"Error fetching page: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_status_pages(url):
    pages = {
        "/server-status": "Apache mod_status/info",
        "/server-info":  "Apache mod_status/info",
        "/status":       "nginx stub_status",
        "/webdav":       "nginx dav"
    }
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    res = []
    for p, desc in pages.items():
        try:
            r = get(f"{url.rstrip('/')}{p}")
            if r.status_code in (200, 401, 403):
                line = f"{p} ({desc}) accessible"
                m = ip_re.search(r.text)
                if m:
                    line += f"; leaked IP: {m.group()}"
                res.append(line)
        except RequestException:
            continue
    return "\n".join(res) or "No status pages found"

def check_files_and_paths(url):
    items = ["info.php", ".git", ".svn", ".hg", ".env", ".DS_Store", "security.txt"]
    paths = ["backup", "admin", "secret"]
    found = []
    for f in items + paths:
        try:
            r = get(f"{url.rstrip('/')}/{f}")
            if r.status_code == 200:
                prefix = "File" if f in items else "Path"
                found.append(f"{prefix} found: /{f}")
        except RequestException:
            continue
    return "\n".join(found) or "No sensitive files or paths found"

def check_external_resources(url):
    try:
        r = get(url)
        links = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', r.text)
        ext = [l for l in set(links) if not urlparse(l).hostname.endswith(".onion")]
        return "External resources:\n" + "\n".join(ext) if ext else "No external resources detected"
    except RequestException as e:
        return f"Error fetching resources: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_cors(url):
    try:
        r = get(url)
        ac = {k: v for k, v in r.headers.items() if k.startswith("Access-Control-")}
        return "CORS headers:\n" + "\n".join(f"{k}: {v}" for k, v in ac.items()) if ac else "No CORS headers"
    except RequestException as e:
        return f"Error fetching headers: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_meta_redirects(url):
    try:
        r = get(url)
        metas = re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', r.text, re.IGNORECASE)
        out = []
        for m in metas:
            c = re.search(r'content=["\']([^"\']+)["\']', m, re.IGNORECASE)
            if c and "url=" in c.group(1).lower():
                tgt = c.group(1).split("url=")[1]
                if tgt.startswith(("http://", "https://")):
                    out.append(tgt)
        return "Meta-refresh redirects:\n" + "\n".join(out) if out else "No meta-refresh to clearnet URLs"
    except RequestException as e:
        return f"Error fetching meta tags: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_robots_sitemap(url):
    out = []
    for path in ["/robots.txt", "/sitemap.xml"]:
        try:
            r = get(f"{url.rstrip('/')}{path}")
            if r.status_code == 200:
                if path == "/robots.txt":
                    lines = [l for l in r.text.splitlines()
                             if l.lower().startswith(("disallow:", "sitemap:"))]
                    if lines:
                        out.append(f"{path} entries:\n" + "\n".join(lines))
                else:
                    locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
                    if locs:
                        out.append(f"{path} locs:\n" + "\n".join(locs))
        except RequestException:
            continue
    return "\n\n".join(out) or "No robots.txt or sitemap.xml entries found"

def check_form_actions(url):
    try:
        r = get(url)
        acts = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        out = [a for a in set(acts)
               if a.startswith(("http://", "https://")) and not urlparse(a).hostname.endswith(".onion")]
        return "Form actions to clearnet:\n" + "\n".join(out) if out else "No clearnet form actions"
    except RequestException as e:
        return f"Error fetching forms: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_websocket_endpoints(url):
    try:
        r = get(url)
        wss = re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', r.text)
        out = [ws for ws in set(wss) if not urlparse(ws).hostname.endswith(".onion")]
        return "WebSocket endpoints to clearnet:\n" + "\n".join(out) if out else "No clearnet WebSocket endpoints"
    except RequestException as e:
        return f"Error fetching WebSocket endpoints: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_proxy_headers(url):
    try:
        r = get(url)
        keys = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded"]
        found = [f"{k}: {r.headers[k]}" for k in keys if k in r.headers]
        return "\n".join(found) if found else "No proxy-related headers"
    except RequestException as e:
        return f"Error fetching proxy headers: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_security_txt(url):
    try:
        r = get(f"{url.rstrip('/')}/.well-known/security.txt")
        return "security.txt:\n" + r.text.strip() if r.status_code == 200 else "security.txt not found"
    except RequestException as e:
        return f"Error fetching security.txt: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_captcha_leak(url):
    try:
        r = get(url)
        if r.status_code != 200:
            return "No page to check for CAPTCHA leaks"
        text = r.text.lower()
        leaks = set(re.findall(
            r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, re.IGNORECASE))
        for path in ("/lua/cap.lua", "/queue.html"):
            if path in text:
                for m in re.findall(r'["\']([^"\']+' + re.escape(path) + r')["\']', text):
                    full = m if m.startswith("http") else f"{url.rstrip('/')}{m}"
                    leaks.add(full)
        real = [u for u in leaks if not urlparse(u).hostname.endswith(".onion")]
        return "Possible CAPTCHA leaks:\n" + "\n".join(real) if real else "No external CAPTCHA resources detected"
    except RequestException as e:
        return f"Error fetching page: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

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
    parser.add_argument("-u", "--url", required=True,
                        help=".onion URL to scan (e.g. abcdef.onion)")
    args = parser.parse_args()

    cfg.timeout = args.timeout
    cfg.sleep   = args.sleep

    raw = args.url
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    dom = urlparse(raw).netloc.lower()
    if not dom.endswith(".onion"):
        console.print(ASCII_LOGO)
        console.print("[red]Error: Provide a valid .onion URL[/red]\n")
        show_help()
        sys.exit(1)
    url = f"http://{dom}"

    if not check_tor_proxy():
        console.print(ASCII_LOGO)
        console.print("[red]Tor proxy not working; start Tor on 127.0.0.1:9050[/red]\n")
        show_help()
        sys.exit(1)

    console.print(ASCII_LOGO)

    tasks = [
        ("Check Tor proxy",     lambda: "OK"),
        ("Detect server",       lambda: detect_server(url)),
        ("Detect favicon",      lambda: detect_favicon(url)),
        ("Favicon in HTML",     lambda: detect_favicon_in_html(url)),
        ("SSH fingerprint",     lambda: check_ssh_fingerprint(url)),
        ("Comments in code",    lambda: check_comments(url)),
        ("Status pages",        lambda: check_status_pages(url)),
        ("Files & paths",       lambda: check_files_and_paths(url)),
        ("External resources",  lambda: check_external_resources(url)),
        ("CORS headers",        lambda: check_cors(url)),
        ("Meta-refresh",        lambda: check_meta_redirects(url)),
        ("Robots & sitemap",    lambda: check_robots_sitemap(url)),
        ("Form actions",        lambda: check_form_actions(url)),
        ("WebSocket endpoints", lambda: check_websocket_endpoints(url)),
        ("Proxy headers",       lambda: check_proxy_headers(url)),
        ("security.txt",        lambda: check_security_txt(url)),
        ("CAPTCHA leak",        lambda: check_captcha_leak(url)),
    ]
    total = len(tasks)
    results = []

    for idx, (desc, fn) in enumerate(tasks, start=1):
        with console.status(f"{idx}/{total} {desc}: in progress"):
            out = fn()
            time.sleep(cfg.sleep)
        console.print(f"[green]{idx}/{total} {desc}: done[/green]")
        results.append((desc, out))

    console.print("\n[bold green]All steps complete[/bold green]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check")
    table.add_column("Result")
    for desc, out in results:
        table.add_row(desc, out.replace("\n", " | "))
    console.print(table)


if __name__ == "__main__":
    main()
