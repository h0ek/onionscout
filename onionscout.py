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
import ssl
import base64
from typing import Optional
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
v0.0.8
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

def set_cookie_header(cookie_str: str):
    # Ustawiamy surowy header Cookie (najbardziej przewidywalne dla wielu ciastek naraz)
    session.headers["Cookie"] = cookie_str.strip()

def get(url, **kwargs):
    timeout = kwargs.pop("timeout", cfg.timeout)
    return session.get(url, timeout=timeout, **kwargs)

def head(url, **kwargs):
    timeout = kwargs.pop("timeout", cfg.timeout)
    return session.head(url, timeout=timeout, **kwargs)

def options(url, **kwargs):
    timeout = kwargs.pop("timeout", cfg.timeout)
    return session.options(url, timeout=timeout, **kwargs)

def show_help():
    console.print(ASCII_LOGO)
    print_help_body()

def print_help_body():
    console.print("Lightweight CLI for basic Tor hidden-service (.onion) security checks\n")
    console.print("usage:")
    console.print("  onionscout [-t TIMEOUT] [-s SLEEP] [--socks HOST:PORT] [--skip-tor-check] [--json] [--cookie COOKIE] [-o OUTPUT] -u URL\n")
    console.print("options:")
    console.print("  -t TIMEOUT           HTTP timeout in seconds (default: 10.0)")
    console.print("  -s SLEEP             seconds between checks (default: 3.0)")
    console.print("  --socks HOST:PORT    Tor SOCKS5h proxy (default: 127.0.0.1:9050)")
    console.print("  --ssh-port PORT      SSH port for fingerprint check (default: 22)")
    console.print("  --skip-tor-check     do not call check.torproject.org")
    console.print("  --json               output JSON instead of a table")
    console.print("  --cookie COOKIE      raw Cookie header, e.g. 'a=b; c=d'")
    console.print("  -o OUTPUT            write report to file (JSON if --json, else TXT)")
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

def report_tor_check(skip: bool) -> str:
    if skip:
        return "Skipped (--skip-tor-check)"
    ok = check_tor_proxy()
    return "OK (Tor SOCKS works via exit check.torproject.org)" if ok else "FAILED (may be expected for pure HS usage)"

def _looks_like_html(raw: bytes, ct: str) -> bool:
    c = (ct or "").lower()
    if "text/html" in c:
        return True
    s = (raw or b"")[:512].lstrip()
    if not s:
        return False
    if s.startswith(b"<!doctype") or s.startswith(b"<html") or s.startswith(b"<head") or s.startswith(b"<body") or s.startswith(b"<"):
        return True
    if b"<html" in s.lower():
        return True
    return False

def _favicon_content_ok(raw: bytes, ct: str) -> bool:
    if not raw or len(raw) < 64:
        return False
    if _looks_like_html(raw, ct):
        return False
    c = (ct or "").lower()
    if c.startswith("image/"):
        return True
    if "application/octet-stream" in c or "binary/octet-stream" in c:
        return True
    if "image/x-icon" in c or "image/vnd.microsoft.icon" in c:
        return True
    if not c:
        return True
    return False

def shodan_favicon_hash_from_bytes(raw_content: bytes) -> int:
    b64 = base64.encodebytes(raw_content)
    return mmh3.hash(b64, signed=True)

def shodan_favicon_query(h: int) -> str:
    return f"http.favicon.hash:{h}"

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
    r = get(url, allow_redirects=False, **kwargs)
    if r.status_code in _REDIRECTS:
        loc = r.headers.get("Location")
        if not loc:
            return r, None
        nxt = urljoin(url, loc)
        pu = urlparse(nxt)
        if pu.scheme not in ("http", "https"):
            return None, nxt
        host = (pu.hostname or "").lower()
        if host.endswith(".onion"):
            r2 = get(nxt, allow_redirects=False, **kwargs)
            return r2, None
        else:
            return None, nxt
    return r, None

EMAIL_RE = re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.IGNORECASE)

# BTC: legacy + bech32
BTC_RE = re.compile(r'\b(?:bc1[ac-hj-np-z02-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')

# ETH
ETH_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

# XMR (uproszczone – wystarczy jako “indicator”)
XMR_RE = re.compile(r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{90,105}\b')

def extract_indicators_from_text(text: str) -> dict:
    t = text or ""
    return {
        "emails": sorted(set(EMAIL_RE.findall(t))),
        "btc": sorted(set(BTC_RE.findall(t))),
        "eth": sorted(set(ETH_RE.findall(t))),
        "xmr": sorted(set(XMR_RE.findall(t))),
    }

def indicators_from_urls(urls: list[str]) -> str:
    agg = {"emails": set(), "btc": set(), "eth": set(), "xmr": set()}

    for u in urls:
        try:
            r, leak = get_onion_follow(u)
            if leak or not r or r.status_code != 200:
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if "html" not in ct:
                continue
            ind = extract_indicators_from_text(r.text or "")
            for k in agg:
                agg[k].update(ind[k])
        except Exception:
            continue

    lines = []
    for k, label in [("emails","Emails"),("btc","BTC"),("eth","ETH"),("xmr","XMR")]:
        vals = sorted(agg[k])
        if vals:
            lines.append(f"{label}:\n" + "\n".join(vals[:30]) + (f"\n… (+{len(vals)-30})" if len(vals) > 30 else ""))
        else:
            lines.append(f"{label}: none")
    return "\n\n".join(lines)

ICON_LINK_RE = re.compile(
    r'<link\s+[^>]*rel=["\']([^"\']*icon[^"\']*)["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE
)

from collections import deque
import hashlib

ASSET_EXT_SKIP = re.compile(r'\.(?:png|jpe?g|gif|webp|svg|ico|mp4|mp3|wav|woff2?|ttf|eot|pdf|zip|rar|7z)$', re.IGNORECASE)

TAG_ATTR_RE = re.compile(
    r'''<(a|link)\b[^>]*(?:href)=["']([^"']+)["']|<(img|script)\b[^>]*(?:src)=["']([^"']+)["']''',
    re.IGNORECASE
)

def _norm_url(base_url: str, u: str) -> Optional[str]:
    if not u:
        return None
    u = u.strip()
    if u.startswith(("mailto:", "javascript:", "data:", "tel:")):
        return None
    full = urljoin(base_url, u)
    pu = urlparse(full)
    if pu.scheme not in ("http", "https"):
        return None
    # wywal fragmenty
    full = full.split("#", 1)[0]
    return full

def _same_onion_host(base_url: str, full_url: str) -> bool:
    b = urlparse(base_url).hostname or ""
    h = urlparse(full_url).hostname or ""
    return b.lower() == h.lower()

def _hash_html(text: str) -> str:
    # normalizacja lekka, żeby drobne różnice mniej przeszkadzały
    t = (text or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
    return hashlib.sha256(t.encode("utf-8", errors="ignore")).hexdigest()

def _get_home_fingerprint(base_url: str) -> Optional[str]:
    try:
        r, leak = get_onion_follow(base_url + "/")
        if leak or not r or r.status_code != 200:
            return None
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if "html" not in ct:
            return None
        return _hash_html(r.text or "")
    except Exception:
        return None

def _looks_like_index_redirect_or_soft404(r, soft404_baseline, home_fp: Optional[str]) -> bool:
    if not r:
        return True
    # jeśli wygląda jak soft404 (Twoja funkcja)
    if looks_like_soft404(r, soft404_baseline):
        return True
    # jeśli 200 i HTML identyczny jak home -> traktuj jak “redirect to index”
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if r.status_code == 200 and "html" in ct and home_fp:
            fp = _hash_html(r.text or "")
            if fp == home_fp:
                return True
    except Exception:
        pass
    return False

def crawl_links(base_url: str, max_urls: int = 80, depth: int = 1) -> list[str]:
    base = base_url.rstrip("/")
    home_fp = _get_home_fingerprint(base)
    soft404_baseline = get_soft404_baseline(base)

    start_urls = [base + "/"]
    # opcjonalnie: dorzuć robots/sitemap jako “seed” (bez bruteforce)
    start_urls += [base + "/robots.txt", base + "/sitemap.xml"]

    q = deque()
    seen = set()
    out = []

    for u in start_urls:
        q.append((u, 0))

    while q and len(out) < max_urls:
        url, d = q.popleft()
        if url in seen:
            continue
        seen.add(url)

        # filtr hosta
        if not _same_onion_host(base, url):
            continue

        # szybki filtr assetów
        if ASSET_EXT_SKIP.search(urlparse(url).path or ""):
            continue

        try:
            r, leak = get_onion_follow(url)
            if leak:
                # tu możesz ewentualnie logować leak jako “znaleziony przez crawl”
                continue
            if not r:
                continue

            ct = (r.headers.get("Content-Type", "") or "").lower()
            # crawlujemy tylko HTML
            if r.status_code != 200 or "html" not in ct:
                continue

            # omijamy “wszystko to index”
            if _looks_like_index_redirect_or_soft404(r, soft404_baseline, home_fp):
                continue

            out.append(url)

            if d >= depth:
                continue

            html = r.text or ""
            for m in TAG_ATTR_RE.finditer(html):
                href = m.group(2) or m.group(4)
                full = _norm_url(base, href)
                if not full:
                    continue
                if not _same_onion_host(base, full):
                    continue
                if full not in seen:
                    q.append((full, d + 1))

        except Exception:
            continue

    return out

def detect_favicon(url):
    ico = f"{url.rstrip('/')}/favicon.ico"
    try:
        r, leak = get_onion_follow(ico)
        if leak:
            return f"Favicon redirect leak → {leak}"
        if r and r.status_code == 200 and r.content:
            ct = r.headers.get("Content-Type", "") or ""
            if not _favicon_content_ok(r.content, ct):
                return f"Favicon at {ico} looks invalid (Content-Type={ct or 'n/a'}, len={len(r.content)})"
            h = shodan_favicon_hash_from_bytes(r.content)
            q = shodan_favicon_query(h)
            return f"Favicon found at {ico}. Shodan hash: {h} | Query: {q}"
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
        for _, href in matches:
            fav_url = urljoin(url, href)
            if fav_url in seen:
                continue
            seen.add(fav_url)
            rf, leak = get_onion_follow(fav_url)
            if leak:
                leaks.append(leak)
                continue
            if rf and rf.status_code == 200 and rf.content:
                ct = rf.headers.get("Content-Type", "") or ""
                if not _favicon_content_ok(rf.content, ct):
                    continue
                h = shodan_favicon_hash_from_bytes(rf.content)
                q = shodan_favicon_query(h)
                return f"Favicon in HTML: {fav_url}. Shodan hash: {h} | Query: {q}"
        if leaks:
            return "Favicon HTML redirect leak(s):\n" + "\n".join(sorted(set(leaks)))
        return "No valid favicon in HTML"
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
        c.connect(
            hostname=host,
            port=ssh_port,
            username="onionscout",
            password=None,
            sock=sock,
            timeout=cfg.timeout,
            banner_timeout=cfg.timeout,
            auth_timeout=cfg.timeout,
            allow_agent=False,
            look_for_keys=False
        )
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

def is_valid_ipv4(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        nums = [int(p) for p in parts]
        return all(0 <= n <= 255 for n in nums)
    except Exception:
        return False

def find_valid_ipv4(text: str) -> Optional[str]:
    for m in IPV4_RE.finditer(text or ""):
        ip = m.group(0)
        if is_valid_ipv4(ip):
            return ip
    return None

def _found_ip_leak(text: str) -> str:
    ip = find_valid_ipv4(text or "")
    return f"; leaked IP: {ip}" if ip else ""

NGINX_STUB_RE = re.compile(
    r"Active connections:\s*\d+.*?server accepts handled requests\s*\d+\s+\d+\s+\d+.*?Reading:\s*\d+\s+Writing:\s*\d+\s+Waiting:\s*\d+",
    re.IGNORECASE | re.DOTALL
)

def check_status_pages(url):
    results = []
    base = url.rstrip("/")

    try:
        u = f"{base}/server-status?auto"
        r = get(u, allow_redirects=False)
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if r.status_code == 200 and ("text" in ct or "plain" in ct) and ("Total Accesses" in r.text) and ("ServerUptimeSeconds" in r.text or "Scoreboard" in r.text):
            results.append(f"/server-status?auto (Apache mod_status) OPEN{_found_ip_leak(r.text)}")
        elif r.status_code in (401, 403):
            results.append("/server-status?auto (Apache mod_status) protected")
    except RequestException:
        pass

    try:
        u = f"{base}/server-status"
        r = get(u, allow_redirects=False)
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if r.status_code == 200 and ("html" in ct) and ("Apache Server Status" in r.text) and ("Scoreboard" in r.text):
            results.append(f"/server-status (Apache mod_status HTML) OPEN{_found_ip_leak(r.text)}")
        elif r.status_code in (401, 403):
            results.append("/server-status (Apache mod_status HTML) protected")
    except RequestException:
        pass

    try:
        u = f"{base}/server-info"
        r = get(u, allow_redirects=False)
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if r.status_code == 200 and ("html" in ct) and ("Apache Server Information" in r.text) and ("Server Module" in r.text):
            results.append("/server-info (Apache mod_info) OPEN")
        elif r.status_code in (401, 403):
            results.append("/server-info (Apache mod_info) protected")
    except RequestException:
        pass

    try:
        u = f"{base}/status"
        r = get(u, allow_redirects=False)
        if r.status_code == 200 and NGINX_STUB_RE.search(r.text or ""):
            results.append("/status (nginx stub_status) OPEN")
        elif r.status_code in (401, 403):
            results.append("/status (nginx stub_status) protected")
    except RequestException:
        pass

    try:
        for path in ("/webdav", "/"):
            u = f"{base}{path}"
            r = options(u, allow_redirects=False)
            dav = r.headers.get("DAV") or r.headers.get("Dav")
            allow = r.headers.get("Allow", "")
            if dav or ("PROPFIND" in allow or "MKCOL" in allow):
                results.append(f"{path} (WebDAV) ENABLED (DAV={dav or 'n/a'}, Allow={allow})")
                break
    except RequestException:
        pass

    return "\n".join(results) if results else "No status pages fingerprinted"

def get_soft404_baseline(base_url: str):
    rand = uuid.uuid4().hex
    try:
        r = get(f"{base_url.rstrip('/')}/{rand}", allow_redirects=False)
        ct = (r.headers.get("Content-Type", "") or "").lower()
        return {
            "status": r.status_code,
            "len": len(r.content or b""),
            "ct": ct,
            "sample": (r.text or "")[:200].lower()
        }
    except Exception:
        return None

def looks_like_soft404(r, baseline) -> bool:
    if not baseline or not r:
        return False
    ct = (r.headers.get("Content-Type", "") or "").lower()
    if "html" not in ct:
        return False
    blen = baseline.get("len", 0) or 0
    rlen = len(r.content or b"")
    if blen > 0:
        ratio = abs(rlen - blen) / blen
        if ratio < 0.12:
            return True
    body = (r.text or "").lower()
    if "not found" in body or "404" in body:
        return True
    bs = baseline.get("sample") or ""
    if bs and bs in body:
        return True
    return False

def check_files_and_paths(url):
    items = ["info.php", ".git", ".svn", ".hg", ".env", ".DS_Store"]
    paths = ["backup", "admin", "secret"]
    found = []
    base = url.rstrip("/")
    baseline = get_soft404_baseline(base)

    for f in items + paths:
        try:
            r = get(f"{base}/{f}", allow_redirects=False)
            if r.status_code == 200:
                if looks_like_soft404(r, baseline):
                    continue
                prefix = "File" if f in items else "Path"
                found.append(f"{prefix} found: /{f}")
        except RequestException:
            continue

    return "\n".join(found) if found else "No sensitive files or paths found"

def check_external_resources(url):
    try:
        r = get(url, allow_redirects=False)
        links = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', r.text or "", re.IGNORECASE)
        ext = [l for l in sorted(set(links)) if not (urlparse(l).hostname or "").endswith(".onion")]
        return "External resources:\n" + "\n".join(ext) if ext else "No external resources detected"
    except Exception as e:
        return f"Error fetching resources: {e}"

PROTO_REL_RE = re.compile(r'(?:src|href)=["\'](//[^"\']+)["\']', re.IGNORECASE)

def check_protocol_relative_links(url: str) -> str:
    try:
        r = get(url, allow_redirects=False)
        links = PROTO_REL_RE.findall(r.text or "")
        out = []
        for l in sorted(set(links)):
            full = "http:" + l
            host = (urlparse(full).hostname or "").lower()
            if host and not host.endswith(".onion"):
                out.append(l)
        return "Protocol-relative (//) external links:\n" + "\n".join(out) if out else "No protocol-relative external links"
    except Exception as e:
        return f"Error checking protocol-relative links: {e}"

def check_cors(url):
    try:
        r = get(url, allow_redirects=False)
        ac = {k: v for k, v in r.headers.items() if k.lower().startswith("access-control-")}
        return "CORS headers:\n" + "\n".join(f"{k}: {v}" for k, v in ac.items()) if ac else "No CORS headers"
    except Exception as e:
        return f"Error fetching headers: {e}"

META_REFRESH_RE = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+>', re.IGNORECASE)
CONTENT_ATTR_RE = re.compile(r'content=["\']([^"\']+)["\']', re.IGNORECASE)

def check_meta_redirects(url):
    try:
        r = get(url, allow_redirects=False)
        metas = META_REFRESH_RE.findall(r.text or "")
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
    out, base = [], url.rstrip("/")

    try:
        r, leak = get_onion_follow(f"{base}/robots.txt")
        if leak:
            out.append(f"/robots.txt redirect leak → {leak}")
        elif r and r.status_code == 200 and (r.content or b""):
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if _looks_like_html(r.content or b"", ct):
                # 200 ale to HTML/index/soft404 -> ignoruj
                pass
            else:
                text = (r.text or "")
                lines = [l for l in text.splitlines()
                         if l.lower().startswith(("disallow:", "sitemap:"))]
                if lines:
                    out.append("/robots.txt entries:\n" + "\n".join(lines))
    except RequestException:
        pass

    try:
        r, leak = get_onion_follow(f"{base}/sitemap.xml")
        if leak:
            out.append(f"/sitemap.xml redirect leak → {leak}")
        elif r and r.status_code == 200 and (r.content or b""):
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if _looks_like_html(r.content or b"", ct):
                # 200 ale to HTML/index/soft404 -> ignoruj
                pass
            else:
                text = (r.text or "")
                locs = re.findall(r"<loc>([^<]+)</loc>", text, re.IGNORECASE)
                if locs:
                    out.append("/sitemap.xml locs:\n" + "\n".join(locs))
    except RequestException:
        pass

    return "\n\n".join(out) if out else "No robots.txt or sitemap.xml entries found"


def check_form_actions(url):
    try:
        r = get(url, allow_redirects=False)
        acts = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', r.text or "", re.IGNORECASE)
        out = [a for a in sorted(set(acts)) if a.startswith(("http://", "https://")) and not (urlparse(a).hostname or "").endswith(".onion")]
        return "Form actions to clearnet:\n" + "\n".join(out) if out else "No clearnet form actions"
    except Exception as e:
        return f"Error fetching forms: {e}"

def check_websocket_endpoints(url):
    try:
        r = get(url, allow_redirects=False)
        wss = re.findall(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', r.text or "", re.IGNORECASE)
        out = [ws for ws in sorted(set(wss)) if not (urlparse(ws).hostname or "").endswith(".onion")]
        return "WebSocket endpoints to clearnet:\n" + "\n".join(out) if out else "No clearnet WebSocket endpoints"
    except Exception as e:
        return f"Error fetching WebSocket endpoints: {e}"

def check_proxy_headers(url):
    try:
        r = get(url, allow_redirects=False)
        keys = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded"]
        found = [f"{k}: {r.headers[k]}" for k in keys if k in r.headers]
        return "\n".join(found) if found else "No proxy-related headers"
    except Exception as e:
        return f"Error fetching proxy headers: {e}"

SECURITYTXT_MAX_BYTES = 200_000  # sanity limit

# Minimalnie sensowne dyrektywy wg spec (wystarczy do odróżniania od HTML/index)
SECURITYTXT_DIRECTIVE_RE = re.compile(
    r'^(Contact|Expires|Encryption|Acknowledgments|Policy|Hiring|Preferred-Languages|Canonical)\s*:\s*.+$',
    re.IGNORECASE
)

def _first_nonempty_line(text: str) -> str:
    for line in (text or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return s
    return ""

def _looks_like_security_txt(body_text: str) -> bool:
    # security.txt to tekst z dyrektywami "Hint: Contact:, Expires:, ..."
    first = _first_nonempty_line(body_text)
    if not first:
        return False
    return bool(SECURITYTXT_DIRECTIVE_RE.match(first))

def _securitytxt_invalid_reason(r) -> Optional[str]:
    # r: requests.Response
    if not r:
        return "no response"
    ct = (r.headers.get("Content-Type", "") or "").lower()
    raw = r.content or b""

    if len(raw) == 0:
        return "empty body"
    if len(raw) > SECURITYTXT_MAX_BYTES:
        return f"too large ({len(raw)} bytes)"

    # Jeśli wygląda jak HTML -> to nie security.txt (najczęstszy błąd)
    if _looks_like_html(raw, ct):
        return f"looks like HTML (Content-Type={ct or 'n/a'})"

    # Jeśli content-type mówi "json/xml/image" itp. raczej nie security.txt
    # (text/plain, text/*, albo brak -> OK)
    if ct and not (ct.startswith("text/") or "text" in ct or "charset=" in ct):
        # nie blokuj agresywnie, ale oznacz jako podejrzane
        # (wiele serwerów daje application/octet-stream)
        if "octet-stream" not in ct:
            return f"suspicious Content-Type ({ct})"

    text = (r.text or "").strip()
    if not _looks_like_security_txt(text):
        # to klucz: 200 + "jakiś tekst" nadal może być index/soft404
        return "does not look like security.txt directives"

    return None

def _fetch_security_txt(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    full = f"{base}{path}"

    try:
        r, leak = get_onion_follow(full)
        if leak:
            return f"{path}: redirect leak → {leak}"

        if not r:
            return f"{path}: no response"

        if r.status_code != 200:
            return f"{path}: not found (HTTP {r.status_code})"

        reason = _securitytxt_invalid_reason(r)
        if reason:
            ct = (r.headers.get("Content-Type", "") or "")
            sample = (r.text or "")[:120].replace("\n", " ").strip()
            return f"{path}: HTTP 200 but NOT valid security.txt ({reason}); Content-Type={ct or 'n/a'}; sample='{sample}'"

        # OK – preview sensownych linii (bez komentarzy)
        lines = []
        for line in (r.text or "").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            lines.append(s)
            if len(lines) >= 12:
                break
        preview = "\n".join(lines)
        return f"{path}: VALID\n{preview}"

    except Exception as e:
        return f"{path}: error ({e})"

def check_security_txt_root(url):
    return _fetch_security_txt(url, "/security.txt")

def check_security_txt(url):
    return _fetch_security_txt(url, "/.well-known/security.txt")

def check_captcha_leak(url):
    try:
        r = get(url, allow_redirects=False)
        if r.status_code != 200 or not (r.text or ""):
            return "No page to check for CAPTCHA leaks"
        text = (r.text or "").lower()
        leaks = set(re.findall(r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, re.IGNORECASE))
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
    try:
        r = head(url, allow_redirects=False)
        etag = r.headers.get("ETag") or r.headers.get("Etag")
        if not etag:
            r = get(url, allow_redirects=False)
            etag = r.headers.get("ETag") or r.headers.get("Etag")
        if etag:
            etag_clean = etag.strip().strip('"').strip("'")
            return f'ETag: "{etag_clean}" | Query: http.headers.etag:"{etag_clean}"'
        return "No ETag header"
    except Exception as e:
        return f"Error fetching ETag: {e}"

def check_onion_location(url: str) -> str:
    try:
        r = get(url, allow_redirects=False)
        val = r.headers.get("Onion-Location") or r.headers.get("onion-location")
        if val:
            return f"Onion-Location: {val}"
        return "No Onion-Location header"
    except Exception as e:
        return f"Error checking Onion-Location: {e}"

LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Served-By",
    "X-Backend",
    "X-Backend-Server",
    "X-Varnish",
    "X-Cache",
    "CF-RAY",
    "X-Amz-Cf-Id",
]

def check_header_leaks(url: str) -> str:
    try:
        r = get(url, allow_redirects=False)
        found = []
        for k in LEAK_HEADERS:
            if k in r.headers:
                found.append(f"{k}: {r.headers.get(k)}")
        return "Header leaks:\n" + "\n".join(found) if found else "No obvious header leaks"
    except Exception as e:
        return f"Error checking header leaks: {e}"

WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/webfinger",
    "/.well-known/host-meta",
    "/.well-known/host-meta.json",
]

def check_well_known(url: str) -> str:
    base = url.rstrip("/")
    hits = []
    for pth in WELL_KNOWN_PATHS:
        try:
            r, leak = get_onion_follow(f"{base}{pth}")
            if leak:
                hits.append(f"{pth} -> redirect leak → {leak}")
                continue
            if r and r.status_code == 200:
                ct = (r.headers.get("Content-Type", "") or "").lower()
                if _looks_like_html(r.content or b"", ct):
                    hits.append(f"{pth} -> 200 but looks like HTML (ct={ct or 'n/a'})")
                else:
                    hits.append(f"{pth} -> 200 ({ct or 'n/a'})")
        except Exception:
            continue
    return "Well-known endpoints:\n" + "\n".join(hits) if hits else "No .well-known endpoints found"

def check_https_tls(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not host:
        return "HTTPS/TLS: invalid host"

    https_url = f"https://{host}/"
    try:
        get(https_url, allow_redirects=False, timeout=min(cfg.timeout, 12))
    except Exception as e:
        return f"HTTPS/TLS: not reachable ({e})"

    try:
        raw = _make_socks_socket(host, 443, timeout=min(cfg.timeout, 12))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        cert = ssock.getpeercert()
        ssock.close()

        if not cert:
            return "HTTPS/TLS: reachable on 443 but certificate not available"

        subj = cert.get("subject") or []
        issr = cert.get("issuer") or []
        subject = ", ".join("=".join(x) for x in subj[0]) if subj and subj[0] else "n/a"
        issuer = ", ".join("=".join(x) for x in issr[0]) if issr and issr[0] else "n/a"
        nb = cert.get("notBefore", "n/a")
        na = cert.get("notAfter", "n/a")
        san = cert.get("subjectAltName", [])
        san_str = ", ".join(f"{t}:{v}" for t, v in san) if san else "n/a"

        return "HTTPS/TLS: reachable\n" + f"Subject: {subject}\nIssuer: {issuer}\nValid: {nb} -> {na}\nSAN: {san_str}"
    except Exception as e:
        return f"HTTPS/TLS: reachable, but TLS inspect failed ({e})"
def render_txt_report(target_url: str, results):
    lines = []
    lines.append(ASCII_LOGO.strip("\n"))
    lines.append("")
    lines.append(f"Target: {target_url}")
    lines.append("")
    for desc, out in results:
        lines.append(f"== {desc} ==")
        lines.append(out or "")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
    
def main():
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = CustomParser(description="Lightweight CLI for basic Tor hidden-service (.onion) security checks")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10.0)")
    parser.add_argument("-s", "--sleep", type=float, default=3.0, help="Seconds between checks (default: 3.0)")
    parser.add_argument("--socks", default="127.0.0.1:9050", help="Tor SOCKS5h proxy (default: 127.0.0.1:9050)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--skip-tor-check", action="store_true", help="Do not call check.torproject.org")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--cookie", help='Raw Cookie header value, e.g. \'a=b; c=d\'')
    parser.add_argument("-o", "--output", help="Write report to file (JSON if --json, else TXT)")
    parser.add_argument("-u", "--url", required=True, help=".onion URL to scan (e.g. abcdef.onion)")
    args = parser.parse_args()

    cfg.timeout = args.timeout
    cfg.sleep = args.sleep
    socks_host, socks_port = parse_socks(args.socks)
    cfg.socks_host, cfg.socks_port = socks_host, socks_port
    configure_tor_proxy(socks_host, socks_port)

    if args.cookie:
        set_cookie_header(args.cookie)
    
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
    crawled_urls = crawl_links(base_url, max_urls=80, depth=1)

    if not args.json:
        console.print(ASCII_LOGO)

    tasks = [
        ("SOCKS/Tor connectivity check", lambda: report_tor_check(args.skip_tor_check)),
        ("Cookie provided", lambda: f"YES ({len(args.cookie)} chars)" if args.cookie else "NO"),
        ("Detect server", lambda: detect_server(base_url)),
        ("HTTPS/TLS sanity", lambda: check_https_tls(base_url)),

        ("Detect favicon", lambda: detect_favicon(base_url)),
        ("Favicon in HTML", lambda: detect_favicon_in_html(base_url)),
        ("ETag header", lambda: check_etag(base_url)),

        ("Onion-Location header", lambda: check_onion_location(base_url)),
        ("Header leaks", lambda: check_header_leaks(base_url)),

        ("SSH fingerprint", lambda: check_ssh_fingerprint(base_url, args.ssh_port)),
        ("Comments in code", lambda: check_comments(base_url)),
        ("Status pages", lambda: check_status_pages(base_url)),

        ("Files & paths", lambda: check_files_and_paths(base_url)),
        ("Well-known endpoints", lambda: check_well_known(base_url)),

        ("External resources", lambda: check_external_resources(base_url)),
        ("Protocol-relative links", lambda: check_protocol_relative_links(base_url)),

        ("CORS headers", lambda: check_cors(base_url)),
        ("Meta-refresh", lambda: check_meta_redirects(base_url)),
        ("Robots & sitemap", lambda: check_robots_sitemap(base_url)),
        ("Form actions", lambda: check_form_actions(base_url)),
        ("WebSocket endpoints", lambda: check_websocket_endpoints(base_url)),
        ("Proxy headers", lambda: check_proxy_headers(base_url)),

        ("security.txt (root)", lambda: check_security_txt_root(base_url)),
        ("security.txt (.well-known)", lambda: check_security_txt(base_url)),

        ("CAPTCHA leak", lambda: check_captcha_leak(base_url)),
        ("Crawl links", lambda: f"Collected {len(crawled_urls)} URLs (depth=1, max=80)"),
        ("Indicators (emails/crypto)", lambda: indicators_from_urls(crawled_urls)),
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
        payload = {k: v for k, v in results}
        out_json = json.dumps(payload, ensure_ascii=False, indent=2)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_json + "\n")
        else:
            print(out_json)
        return

    console.print("\n[bold green]All steps complete[/bold green]\n")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="bold")
    table.add_column("Result")
    for desc, out in results:
        table.add_row(desc, (out or "").replace("\n", " | "))
    console.print(table)

    if args.output:
        txt = render_txt_report(base_url, results)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(txt)
        console.print(f"\n[cyan]Saved report to: {args.output}[/cyan]")

if __name__ == "__main__":
    main()
