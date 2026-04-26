#!/usr/bin/env python3
from __future__ import annotations

import sys
import re
import time
import json
import argparse
import socket
import requests
import urllib3
import mmh3
import paramiko
import uuid
import ssl
import base64
import hashlib
from dataclasses import dataclass
from typing import Optional, Any
from urllib.parse import urlparse, urljoin
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectTimeout, ReadTimeout, ConnectionError, SSLError, ProxyError, RequestException
from rich.console import Console
from rich.table import Table
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import socks
except Exception:
    socks = None

try:
    from selectolax.parser import HTMLParser as SelectolaxHTMLParser
except Exception:
    SelectolaxHTMLParser = None

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except Exception:
    x509 = None
    default_backend = None

ASCII_LOGO = r"""
 ▗▄▖ ▄▄▄▄  ▄  ▄▄▄  ▄▄▄▄       ▗▄▄▖▗▞▀▘ ▄▄▄  █  ▐▌   ■
▐▌ ▐▌█   █ ▄ █   █ █   █     ▐▌   ▝▚▄▖█   █ ▀▄▄▞▘▗▄▟▙▄▖
▐▌ ▐▌█   █ █ ▀▄▄▄▀ █   █      ▝▀▚▖    ▀▄▄▄▀        ▐▌
▝▚▄▞▘      █                 ▗▄▄▞▘                 ▐▌
                                                   ▐▌
v0.1.3
"""

console = Console()
_REDIRECTS = {301, 302, 303, 307, 308}
SECURITYTXT_MAX_BYTES = 200_000


@dataclass
class Config:
    http_timeout: float = 10.0
    ssh_timeout: float = 10.0
    tls_timeout: float = 12.0
    sleep: float = 1.0
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    insecure_https: bool = False
    no_crawl: bool = False
    crawl_max_urls: int = 80
    crawl_depth: int = 1
    scheme: str = "auto"
    retries: int = 2
    workers: int = 4


cfg = Config()

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
})


def rebuild_retry_adapter() -> None:
    retry = Retry(
        total=4,
        connect=3,
        read=2,
        backoff_factor=0.5,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)


rebuild_retry_adapter()


def configure_tor_proxy(host: str, port: int) -> None:
    proxy = f"socks5h://{host}:{port}"
    session.proxies = {"http": proxy, "https": proxy}


def set_cookie_header(cookie_str: str) -> None:
    session.headers["Cookie"] = cookie_str.strip()


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.link_hrefs: list[tuple[str, str]] = []
        self.anchor_hrefs: list[str] = []
        self.form_actions: list[str] = []
        self.meta_refresh_targets: list[str] = []
        self.canonical_urls: list[str] = []
        self.alternate_urls: list[str] = []
        self.preconnect_urls: list[str] = []
        self.prefetch_urls: list[str] = []
        self.preload_urls: list[str] = []
        self.og_urls: list[str] = []
        self.twitter_urls: list[str] = []
        self.script_srcs: list[str] = []
        self.img_srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "a" and a.get("href"):
            self.anchor_hrefs.append(a["href"])

        if tag == "link":
            rel = (a.get("rel") or "").lower()
            href = a.get("href", "")
            if href:
                self.link_hrefs.append((rel, href))
            if "icon" in rel and href:
                self.link_hrefs.append(("icon", href))
            if "canonical" in rel and href:
                self.canonical_urls.append(href)
            if "alternate" in rel and href:
                self.alternate_urls.append(href)
            if "preconnect" in rel and href:
                self.preconnect_urls.append(href)
            if "prefetch" in rel and href:
                self.prefetch_urls.append(href)
            if "preload" in rel and href:
                self.preload_urls.append(href)

        if tag == "form" and a.get("action"):
            self.form_actions.append(a["action"])

        if tag == "meta":
            http_equiv = (a.get("http-equiv") or "").lower()
            content = a.get("content", "")
            prop = (a.get("property") or "").lower()
            name = (a.get("name") or "").lower()
            if http_equiv == "refresh":
                low = content.lower()
                if "url=" in low:
                    self.meta_refresh_targets.append(content.split("=", 1)[1].strip())
            if prop == "og:url" and content:
                self.og_urls.append(content)
            if name in {"twitter:url", "twitter:image", "twitter:image:src"} and content:
                self.twitter_urls.append(content)

        if tag == "script" and a.get("src"):
            self.script_srcs.append(a["src"])

        if tag == "img" and a.get("src"):
            self.img_srcs.append(a["src"])


def html_extract_stdlib(text: str) -> LinkExtractor:
    parser = LinkExtractor()
    try:
        parser.feed(text or "")
    except Exception:
        pass
    return parser


def html_extract_selectolax(text: str) -> Optional[LinkExtractor]:
    if SelectolaxHTMLParser is None:
        return None
    try:
        tree = SelectolaxHTMLParser(text or "")
        out = LinkExtractor()

        for n in tree.css("a[href]"):
            out.anchor_hrefs.append(n.attributes.get("href", ""))

        for n in tree.css("link[href]"):
            rel = (n.attributes.get("rel", "") or "").lower()
            href = n.attributes.get("href", "") or ""
            if href:
                out.link_hrefs.append((rel, href))
            if "icon" in rel and href:
                out.link_hrefs.append(("icon", href))
            if "canonical" in rel and href:
                out.canonical_urls.append(href)
            if "alternate" in rel and href:
                out.alternate_urls.append(href)
            if "preconnect" in rel and href:
                out.preconnect_urls.append(href)
            if "prefetch" in rel and href:
                out.prefetch_urls.append(href)
            if "preload" in rel and href:
                out.preload_urls.append(href)

        for n in tree.css("form[action]"):
            out.form_actions.append(n.attributes.get("action", ""))

        for n in tree.css("script[src]"):
            out.script_srcs.append(n.attributes.get("src", ""))

        for n in tree.css("img[src]"):
            out.img_srcs.append(n.attributes.get("src", ""))

        for n in tree.css("meta"):
            attrs = n.attributes
            http_equiv = (attrs.get("http-equiv", "") or "").lower()
            content = attrs.get("content", "") or ""
            prop = (attrs.get("property", "") or "").lower()
            name = (attrs.get("name", "") or "").lower()

            if http_equiv == "refresh" and "url=" in content.lower():
                out.meta_refresh_targets.append(content.split("=", 1)[1].strip())
            if prop == "og:url" and content:
                out.og_urls.append(content)
            if name in {"twitter:url", "twitter:image", "twitter:image:src"} and content:
                out.twitter_urls.append(content)

        return out
    except Exception:
        return None


def html_extract(text: str) -> LinkExtractor:
    parsed = html_extract_selectolax(text)
    if parsed is not None:
        return parsed
    return html_extract_stdlib(text)


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
OBF_EMAIL_RE = re.compile(
    r"\b([A-Z0-9._%+-]{2,})\s*(?:\(|\[|\{)?\s*(?:at)\s*(?:\)|\]|\})?\s*"
    r"([A-Z0-9.-]{2,})\s*(?:(?:\(|\[|\{)?\s*(?:dot)\s*(?:\)|\]|\})?\s*([A-Z]{2,}))?\b",
    re.IGNORECASE,
)
MAILTO_RE = re.compile(r"mailto:([^\\\"\'\\s<>]+)", re.IGNORECASE)
PLACEHOLDER_EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "localdomain"}
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{90,105}\b")
ICON_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->", re.IGNORECASE)
WEBSOCKET_RE = re.compile(r'new\s+WebSocket\(["\'](ws[s]?://[^"\']+)["\']', re.IGNORECASE)
PROTO_REL_RE = re.compile(r'(?:src|href)=["\'](//[^"\']+)["\']', re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{3}\b|\b(?:\d{1,3}\.){3}\d{1,2}\b")
NGINX_STUB_RE = re.compile(
    r"Active connections:\s*\d+.*?server accepts handled requests\s*\d+\s+\d+\s+\d+.*?Reading:\s*\d+\s+Writing:\s*\d+\s+Waiting:\s*\d+",
    re.IGNORECASE | re.DOTALL,
)
SECURITYTXT_DIRECTIVE_RE = re.compile(
    r"^(Contact|Expires|Encryption|Acknowledgments|Policy|Hiring|Preferred-Languages|Canonical)\s*:\s*.+$",
    re.IGNORECASE,
)
ASSET_EXT_SKIP = re.compile(r"\.(?:png|jpe?g|gif|webp|svg|ico|mp4|mp3|wav|woff2?|ttf|eot|pdf|zip|rar|7z)$", re.IGNORECASE)

LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Version",
    "X-Generator", "X-Drupal-Cache", "X-Served-By", "X-Backend", "X-Backend-Server", "X-Varnish",
    "X-Cache", "CF-RAY", "X-Amz-Cf-Id",
]

WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/webfinger",
    "/.well-known/host-meta",
    "/.well-known/host-meta.json",
]


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    if not host.endswith(".onion"):
        raise ValueError("Provide a valid .onion URL")
    port = f":{p.port}" if p.port else ""
    path = p.path or ""
    base = f"{p.scheme or 'http'}://{host}{port}"
    return base + path




def _base_from_parsed(p) -> str:
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{host}{port}"


def _base_for_scheme(p, scheme: str) -> str:
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port else ""
    return f"{scheme}://{host}{port}"


class _WarningsSilenced:
    def __enter__(self):
        urllib3.disable_warnings(InsecureRequestWarning)
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def probe_origin(base_url: str, timeout: float = 8.0) -> dict[str, Any]:
    # Intentional verify=False here: this is only an origin reachability probe.
    # Many onion HTTPS services use self-signed or non-public CA certificates.
    try:
        with _WarningsSilenced():
            res = fetch_with_policy(base_url, timeout=timeout, max_hops=2, verify=False)
        r = res.get("response")
        if r is not None:
            final_url = res.get("final_url") or base_url
            final_scheme = urlparse(final_url).scheme
            return {
                "url": base_url,
                "ok": True,
                "status_code": r.status_code,
                "final_url": final_url,
                "final_scheme": final_scheme,
                "redirect_chain": res.get("redirect_chain", []),
                "reason": f"HTTP {r.status_code}",
            }
        return {
            "url": base_url,
            "ok": False,
            "reason": res.get("error", "no response"),
            "error_kind": res.get("error_kind", "unknown"),
            "final_url": res.get("final_url", base_url),
            "redirect_chain": res.get("redirect_chain", []),
        }
    except Exception as e:
        info = classify_network_error(e)
        return {
            "url": base_url,
            "ok": False,
            "reason": info["error"],
            "error_kind": info["kind"],
            "final_url": base_url,
            "redirect_chain": [],
        }


def choose_working_origin(raw_url: str, scheme_mode: str = "auto") -> tuple[str, dict[str, Any]]:
    p = urlparse(raw_url)
    attempts = []

    if scheme_mode not in {"auto", "http", "https"}:
        scheme_mode = "auto"

    if scheme_mode in {"http", "https"}:
        candidate = _base_for_scheme(p, scheme_mode)
        probe = probe_origin(candidate, timeout=min(cfg.http_timeout, 8.0))
        attempts.append(probe)
        selected = probe.get("final_url") or candidate
        if urlparse(selected).path:
            selected = _base_for_scheme(urlparse(selected), urlparse(selected).scheme)
        return selected.rstrip("/"), {"mode": scheme_mode, "selected": selected.rstrip("/"), "attempts": attempts}

    candidates = []
    preferred = _base_from_parsed(p)
    candidates.append(preferred)

    # In auto mode prefer HTTPS, but also test HTTP because many onion services are HTTP-only.
    https_base = _base_for_scheme(p, "https")
    http_base = _base_for_scheme(p, "http")
    for c in (https_base, http_base):
        if c not in candidates:
            candidates.append(c)

    for c in candidates:
        probe = probe_origin(c, timeout=min(cfg.http_timeout, 8.0))
        attempts.append(probe)

    ok_attempts = [a for a in attempts if a.get("ok")]
    if not ok_attempts:
        return preferred.rstrip("/"), {
            "mode": "auto",
            "selected": preferred.rstrip("/"),
            "attempts": attempts,
            "note": "no working HTTP/HTTPS origin found",
        }

    # Prefer effective HTTPS, then any HTTPS input, then first working.
    effective_https = [a for a in ok_attempts if a.get("final_scheme") == "https"]
    if effective_https:
        chosen = effective_https[0]
    else:
        chosen = ok_attempts[0]

    selected = chosen.get("final_url") or chosen.get("url")
    sp = urlparse(selected)
    selected_base = _base_for_scheme(sp, sp.scheme).rstrip("/")

    note = None
    if sp.scheme == "http":
        note = "using http origin for web checks"
    elif sp.scheme == "https":
        note = "using https origin for web checks"

    return selected_base, {
        "mode": "auto",
        "selected": selected_base,
        "attempts": attempts,
        "note": note,
    }


def parse_socks(s: str) -> tuple[str, int]:
    host, port = s.rsplit(":", 1)
    return host.strip(), int(port.strip())



def classify_network_error(e: Exception) -> dict[str, str]:
    msg = str(e)
    low = msg.lower()

    if isinstance(e, (ConnectTimeout, ReadTimeout)) or "timed out" in low or "timeout" in low:
        kind = "timeout"
    elif isinstance(e, ConnectionError) and ("refused" in low or "0x05" in low):
        kind = "refused"
    elif "reset by peer" in low or "connection reset" in low:
        kind = "reset"
    elif isinstance(e, SSLError) or "ssl" in low or "tls" in low:
        kind = "tls_error"
    elif isinstance(e, ProxyError) or "socks" in low:
        kind = "proxy_error"
    elif "host unreachable" in low or "general socks server failure" in low:
        kind = "tor_circuit"
    else:
        kind = "network_error"

    return {
        "kind": kind,
        "error": f"{type(e).__name__}: {e}",
    }


def should_retry_error(kind: str) -> bool:
    return kind in {"timeout", "reset", "proxy_error", "tor_circuit", "network_error"}


def request(
    method: str,
    url: str,
    *,
    timeout: Optional[float] = None,
    allow_redirects: bool = False,
    verify: Optional[bool] = None,
    headers: Optional[dict[str, str]] = None,
):
    if timeout is None:
        timeout = cfg.http_timeout
    if verify is None:
        verify = not cfg.insecure_https

    last_error = None
    attempts = max(1, cfg.retries + 1)

    for attempt in range(attempts):
        try:
            return session.request(method, url, timeout=timeout, allow_redirects=allow_redirects, verify=verify, headers=headers)
        except Exception as e:
            info = classify_network_error(e)
            last_error = e
            if attempt >= attempts - 1 or not should_retry_error(info["kind"]):
                raise
            time.sleep(min(0.35 * (attempt + 1), 1.5))

    if last_error:
        raise last_error
    raise RuntimeError("request failed without exception")


def same_onion_host(base_url: str, full_url: str) -> bool:
    b = (urlparse(base_url).hostname or "").lower()
    h = (urlparse(full_url).hostname or "").lower()
    return bool(b and h and b == h)


def fetch_with_policy(
    url: str,
    *,
    method: str = "GET",
    timeout: Optional[float] = None,
    max_hops: int = 2,
    verify: Optional[bool] = None,
):
    visited = []
    current = url

    for _ in range(max_hops + 1):
        try:
            r = request(method, current, timeout=timeout, allow_redirects=False, verify=verify)
        except Exception as e:
            info = classify_network_error(e)
            return {
                "response": None,
                "leak": None,
                "redirect_chain": visited,
                "final_url": current,
                "error": info["error"],
                "error_kind": info["kind"],
            }

        visited.append(current)

        if r.status_code not in _REDIRECTS:
            return {
                "response": r,
                "leak": None,
                "redirect_chain": visited[:-1],
                "final_url": current,
                "status_code": r.status_code,
            }

        loc = r.headers.get("Location")
        if not loc:
            return {"response": r, "leak": None, "redirect_chain": visited, "final_url": current, "status_code": r.status_code}

        nxt = urljoin(current, loc)
        pu = urlparse(nxt)

        if pu.scheme not in ("http", "https"):
            return {"response": None, "leak": nxt, "redirect_chain": visited, "final_url": current}

        host = (pu.hostname or "").lower()
        if not host.endswith(".onion"):
            return {"response": None, "leak": nxt, "redirect_chain": visited, "final_url": current}

        current = nxt

    return {"response": None, "leak": None, "redirect_chain": visited, "final_url": current, "error": "too many redirects", "error_kind": "redirect_loop"}


def finding(name: str, status: str, risk: str, evidence: Any, raw: Any = None, finding_type: str = "info") -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "finding_type": finding_type,
        "risk": risk,
        "evidence": evidence,
        "raw": raw,
    }


def error_finding(name: str, e: Exception) -> dict[str, Any]:
    return finding(name, "error", "info", f"{type(e).__name__}: {e}", raw={"exception": repr(e)}, finding_type="internal")


def check_tor_proxy() -> dict[str, Any]:
    name = "SOCKS/Tor connectivity check"
    try:
        r = request("GET", "http://check.torproject.org", timeout=5, allow_redirects=True, verify=False)
        ok = "Congratulations" in (r.text or "")
        return finding(name, "ok" if ok else "warn", "low", "Tor exit connectivity confirmed" if ok else "Tor exit check failed (may be expected for pure onion usage)")
    except Exception as e:
        return error_finding(name, e)


def check_cookie_present(cookie: Optional[str]) -> dict[str, Any]:
    return finding("Cookie provided", "ok", "info", f"YES ({len(cookie)} chars)" if cookie else "NO")


def detect_server(url: str) -> dict[str, Any]:
    name = "Detect server"
    try:
        info = []
        main = fetch_with_policy(url)
        if main.get("leak"):
            return finding(name, "fail", "high", f"Homepage redirect leak \u2192 {main['leak']}", raw=main, finding_type="deanon")
        r = main.get("response")
        if not r:
            return finding(name, "warn", "low", "No HTTP response", raw=main)
        hdr = r.headers.get("Server", "")
        if hdr:
            info.append(f"Server header: {hdr}")
        rand = uuid.uuid4().hex
        r404 = request("GET", f"{url.rstrip('/')}/{rand}", allow_redirects=False)
        if r404.status_code == 404 and r404.text:
            m = re.search(r"(apache|nginx|lighttpd)(?:/([\d\.]+))?", r404.text.lower())
            if m:
                name_map = {"apache": "Apache", "nginx": "nginx", "lighttpd": "lighttpd"}
                ver = f"/{m.group(2)}" if m.group(2) else ""
                info.append(f"Error page fingerprint: {name_map[m.group(1)]}{ver}")
        return finding(name, "ok" if info else "info", "low", info or "Web server not detected")
    except Exception as e:
        return error_finding(name, e)


def _looks_like_html(raw: bytes, ct: str) -> bool:
    c = (ct or "").lower()
    if "text/html" in c or "application/xhtml+xml" in c:
        return True
    s = (raw or b"")[:512].lstrip()
    if not s:
        return False
    if s.startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<")):
        return True
    return b"<html" in s.lower()


def _favicon_content_ok(raw: bytes, ct: str) -> bool:
    if not raw or len(raw) < 64:
        return False
    if _looks_like_html(raw, ct):
        return False
    c = (ct or "").lower()
    return (
        c.startswith("image/") or
        "application/octet-stream" in c or
        "binary/octet-stream" in c or
        "image/x-icon" in c or
        "image/vnd.microsoft.icon" in c or
        not c
    )


def shodan_favicon_hash_from_bytes(raw_content: bytes) -> int:
    return mmh3.hash(base64.encodebytes(raw_content), signed=True)


def check_favicon(url: str) -> dict[str, Any]:
    name = "Detect favicon"
    try:
        ico = f"{url.rstrip('/')}/favicon.ico"
        data = fetch_with_policy(ico)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Favicon redirect leak \u2192 {data['leak']}", raw=data, finding_type="deanon")
        r = data.get("response")
        if r and r.status_code == 200 and r.content:
            ct = r.headers.get("Content-Type", "") or ""
            if not _favicon_content_ok(r.content, ct):
                return finding(name, "warn", "low", f"Invalid favicon-like response (Content-Type={ct or 'n/a'}, len={len(r.content)})", raw={"content_type": ct, "len": len(r.content)})
            h = shodan_favicon_hash_from_bytes(r.content)
            return finding(name, "ok", "low", [f"Favicon at {ico}", f"Shodan hash: {h}", f"Query: http.favicon.hash:{h}"], raw={"hash": h, "url": ico})
        return finding(name, "info", "info", "No favicon at /favicon.ico")
    except Exception as e:
        return error_finding(name, e)


def check_favicon_in_html(url: str) -> dict[str, Any]:
    name = "Favicon in HTML"
    try:
        home = fetch_with_policy(url)
        if home.get("leak"):
            return finding(name, "fail", "high", f"Homepage redirect leak \u2192 {home['leak']}", raw=home, finding_type="deanon")
        r = home.get("response")
        if not r:
            return finding(name, "warn", "low", "No homepage response")
        parser = html_extract(r.text or "")
        seen = set()
        leaks = []
        for rel, href in parser.link_hrefs:
            if "icon" not in rel:
                continue
            fav_url = urljoin(url, href)
            if fav_url in seen:
                continue
            seen.add(fav_url)
            res = fetch_with_policy(fav_url)
            if res.get("leak"):
                leaks.append(res["leak"])
                continue
            rf = res.get("response")
            if rf and rf.status_code == 200 and rf.content and _favicon_content_ok(rf.content, rf.headers.get("Content-Type", "") or ""):
                h = shodan_favicon_hash_from_bytes(rf.content)
                return finding(name, "ok", "low", [f"Favicon in HTML: {fav_url}", f"Shodan hash: {h}", f"Query: http.favicon.hash:{h}"], raw={"hash": h, "url": fav_url})
        if leaks:
            return finding(name, "fail", "high", sorted(set(leaks)), raw={"leaks": leaks}, finding_type="deanon")
        return finding(name, "info", "info", "No valid favicon in HTML")
    except Exception as e:
        return error_finding(name, e)


def check_etag(url: str) -> dict[str, Any]:
    name = "ETag header"
    try:
        data = fetch_with_policy(url, method="HEAD")
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {data['leak']}", raw=data, finding_type="deanon")
        r = data.get("response")
        etag = None
        if r:
            etag = r.headers.get("ETag") or r.headers.get("Etag")
        if not etag:
            data = fetch_with_policy(url)
            if data.get("leak"):
                return finding(name, "fail", "high", f"Redirect leak \u2192 {data['leak']}", raw=data, finding_type="deanon")
            r = data.get("response")
            if r:
                etag = r.headers.get("ETag") or r.headers.get("Etag")
        if etag:
            etag_clean = etag.strip().strip('"').strip("'")
            return finding(name, "ok", "low", [f'ETag: "{etag_clean}"', f"Query: http.headers.etag:{json.dumps(etag_clean)}"], raw={"etag": etag_clean})
        return finding(name, "info", "info", "No ETag header")
    except Exception as e:
        return error_finding(name, e)


def _make_socks_socket(host: str, port: int, timeout: float):
    if not socks:
        raise RuntimeError("PySocks not installed")
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, cfg.socks_host, cfg.socks_port, rdns=True)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def check_ssh_fingerprint(url: str, ssh_port: int = 22) -> dict[str, Any]:
    name = "SSH fingerprint"
    host = urlparse(url).hostname or ""
    if not host:
        return finding(name, "error", "info", "Invalid host")
    try:
        sock = _make_socks_socket(host, ssh_port, cfg.ssh_timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = cfg.ssh_timeout
        transport.start_client(timeout=cfg.ssh_timeout)
        key = transport.get_remote_server_key()
        fp = key.get_fingerprint()
        hex_fp = ":".join(f"{b:02x}" for b in fp)
        transport.close()
        return finding(name, "ok", "low", f"SSH Fingerprint: {hex_fp} ({key.get_name()})", raw={"fingerprint": hex_fp, "key_type": key.get_name(), "port": ssh_port})
    except Exception as e:
        return finding(name, "info", "info", f"SSH not exposed or handshake failed: {e}", raw={"port": ssh_port})



SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", re.IGNORECASE),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret": re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|bearer|authorization)\b\s*[:=]\s*[\"']?[^\"'\s<>]{8,}"),
    "jwt": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
}


def analyze_comment_text(comments: list[str]) -> dict[str, Any]:
    joined = "\n".join(comments)
    ips = sorted(set(ip for ip in IPV4_RE.findall(joined) if is_valid_ipv4(ip)))
    urls = sorted(set(SECRET_PATTERNS["url"].findall(joined)))
    secret_hits = []

    for pname, rx in SECRET_PATTERNS.items():
        if pname == "url":
            continue
        for m in rx.finditer(joined):
            val = m.group(0)
            if len(val) > 120:
                val = val[:120] + "..."
            secret_hits.append({"type": pname, "match": val})

    boring = {"-", "--", "\u2014", "so meta", "title", "styles", "rss", "async scripts"}
    interesting = []
    for c in comments:
        clean = c.strip()
        if not clean or clean.lower() in boring:
            continue
        if len(clean) == 1 and not clean.isalnum():
            continue
        interesting.append(clean)

    return {
        "comments_preview": interesting[:30],
        "ips": ips[:30],
        "urls": urls[:50],
        "secret_candidates": secret_hits[:30],
        "total_comments": len(comments),
    }



def check_comments(url: str) -> dict[str, Any]:
    name = "Comments in code"
    try:
        data = fetch_with_policy(url)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {data['leak']}", raw=data, finding_type="deanon")
        r = data.get("response")
        if not r:
            return finding(name, "warn", "low", f"No response ({data.get('error', 'unknown error')})", raw=data)
        comments = []
        for c in ICON_COMMENT_RE.findall(r.text or ""):
            for line in c.splitlines():
                line = line.strip()
                if line:
                    comments.append(line)
        if not comments:
            return finding(name, "info", "info", "No comments in code")

        analysis = analyze_comment_text(comments)
        has_secret = bool(analysis["secret_candidates"])
        has_ip_or_url = bool(analysis["ips"] or analysis["urls"])
        status = "warn" if has_secret or has_ip_or_url or analysis["comments_preview"] else "info"
        risk = "high" if has_secret else ("medium" if has_ip_or_url else "low")
        return finding(name, status, risk, analysis, raw=analysis, finding_type="leak")
    except Exception as e:
        return error_finding(name, e)


def is_valid_ipv4(ip: str) -> bool:
    try:
        nums = [int(p) for p in ip.split(".")]
        return len(nums) == 4 and all(0 <= n <= 255 for n in nums)
    except Exception:
        return False


def find_valid_ipv4(text: str) -> Optional[str]:
    for m in IPV4_RE.finditer(text or ""):
        if is_valid_ipv4(m.group(0)):
            return m.group(0)
    return None


def check_status_pages(url: str) -> dict[str, Any]:
    name = "Status pages"
    try:
        base = url.rstrip("/")
        results = []

        def add_open(u: str, label: str, body: str):
            ip = find_valid_ipv4(body or "")
            msg = f"{u} {label} OPEN"
            if ip:
                msg += f"; leaked IP: {ip}"
            results.append(msg)

        checks = [
            (f"{base}/server-status?auto", "Apache mod_status auto"),
            (f"{base}/server-status", "Apache mod_status HTML"),
            (f"{base}/server-info", "Apache mod_info"),
            (f"{base}/status", "nginx stub_status"),
        ]

        for target, label in checks:
            res = fetch_with_policy(target)
            if res.get("leak"):
                results.append(f"{target} redirect leak \u2192 {res['leak']}")
                continue
            r = res.get("response")
            if not r:
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            txt = r.text or ""
            if target.endswith("/server-status?auto") and r.status_code == 200 and "Total Accesses" in txt and ("ServerUptimeSeconds" in txt or "Scoreboard" in txt):
                add_open("/server-status?auto", label, txt)
            elif target.endswith("/server-status") and r.status_code == 200 and "html" in ct and "Apache Server Status" in txt and "Scoreboard" in txt:
                add_open("/server-status", label, txt)
            elif target.endswith("/server-info") and r.status_code == 200 and "Apache Server Information" in txt and "Server Module" in txt:
                results.append("/server-info Apache mod_info OPEN")
            elif target.endswith("/status") and r.status_code == 200 and NGINX_STUB_RE.search(txt):
                results.append("/status nginx stub_status OPEN")
            elif r.status_code in (401, 403):
                results.append(f"{urlparse(target).path} protected")

        for path in ("/webdav", "/"):
            target = f"{base}{path}"
            res = fetch_with_policy(target, method="OPTIONS")
            if res.get("leak"):
                results.append(f"{path} WebDAV redirect leak \u2192 {res['leak']}")
                continue
            r = res.get("response")
            if not r:
                continue
            dav = r.headers.get("DAV") or r.headers.get("Dav")
            allow = r.headers.get("Allow", "")
            if dav or ("PROPFIND" in allow or "MKCOL" in allow):
                results.append(f"{path} WebDAV ENABLED (DAV={dav or 'n/a'}, Allow={allow})")
                break

        if not results:
            return finding(name, "info", "info", "No status pages fingerprinted")
        risk = "high" if any("OPEN" in x for x in results) else "medium"
        status = "warn" if any("OPEN" in x or "leak" in x for x in results) else "info"
        return finding(name, status, risk, results, raw={"count": len(results)})
    except Exception as e:
        return error_finding(name, e)


def get_soft404_baseline(base_url: str):
    rand = uuid.uuid4().hex
    try:
        r = request("GET", f"{base_url.rstrip('/')}/{rand}", allow_redirects=False)
        return {
            "status": r.status_code,
            "len": len(r.content or b""),
            "sample": (r.text or "")[:120].lower(),
        }
    except Exception:
        return None


def text_similarity(a: str, b: str) -> float:
    sa = set(re.findall(r"\w+", (a or "").lower()))
    sb = set(re.findall(r"\w+", (b or "").lower()))
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / max(len(sa | sb), 1)


def looks_like_soft404(r, baseline) -> bool:
    if not baseline or not r:
        return False
    ct = (r.headers.get("Content-Type", "") or "").lower()
    if "html" not in ct and "xhtml" not in ct:
        return False
    blen = baseline.get("len", 0) or 0
    rlen = len(r.content or b"")
    if blen > 0:
        ratio = abs(rlen - blen) / blen
        if ratio < 0.10:
            return True
    body = (r.text or "").lower()
    if "not found" in body or ">404<" in body or "404 " in body:
        return True
    bs = baseline.get("sample") or ""
    if bs and text_similarity(bs, body[:600]) > 0.80:
        return True
    return False


def check_files_and_paths(url: str) -> dict[str, Any]:
    name = "Files & paths"
    try:
        items = ["info.php", ".git", ".svn", ".hg", ".env", ".DS_Store"]
        paths = ["backup", "admin", "secret"]
        found = []
        baseline = get_soft404_baseline(url.rstrip("/"))
        for f in items + paths:
            target = f"{url.rstrip('/')}/{f}"
            res = fetch_with_policy(target)
            if res.get("leak"):
                found.append(f"/{f} redirect leak \u2192 {res['leak']}")
                continue
            r = res.get("response")
            if r and r.status_code == 200 and not looks_like_soft404(r, baseline):
                prefix = "File" if f in items else "Path"
                found.append(f"{prefix} found: /{f}")
        if not found:
            return finding(name, "info", "info", "No sensitive files or paths found")
        return finding(name, "warn", "medium", found, raw={"count": len(found)})
    except Exception as e:
        return error_finding(name, e)


def _resolve_candidates(base_url: str, values: list[str]) -> list[str]:
    out = []
    for v in values:
        if not v:
            continue
        out.append(urljoin(base_url, v))
    return sorted(set(out))


def _is_clearnet(full: str) -> bool:
    host = (urlparse(full).hostname or "").lower()
    return bool(host) and not host.endswith(".onion")




def check_external_resources(url: str) -> dict[str, Any]:
    name = "External resources"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")

        r = res.get("response")
        if not r:
            return finding(
                name,
                "warn",
                "low",
                f"No response ({res.get('error_kind', 'unknown')}: {res.get('error', 'unknown error')})",
                raw=res,
            )

        p = html_extract(r.text or "")

        external_links = [x for x in _resolve_candidates(url, p.anchor_hrefs) if _is_clearnet(x)]

        active_resources = []
        active_resources += [x for x in _resolve_candidates(url, p.script_srcs) if _is_clearnet(x)]
        active_resources += [x for x in _resolve_candidates(url, p.img_srcs) if _is_clearnet(x)]

        for rel, href in p.link_hrefs:
            full = urljoin(url, href)
            if not _is_clearnet(full):
                continue

            if any(x in rel for x in ("stylesheet", "icon", "preload", "prefetch", "preconnect", "dns-prefetch", "modulepreload")):
                active_resources.append(full)
            else:
                external_links.append(full)

        external_links = sorted(set(external_links))
        active_resources = sorted(set(active_resources))

        evidence = {
            "active_resources": active_resources[:100],
            "external_links": external_links[:100],
            "active_count": len(active_resources),
            "link_count": len(external_links),
        }

        if active_resources:
            return finding(name, "warn", "high", evidence, raw=evidence, finding_type="dependency")

        if external_links:
            return finding(name, "info", "low", evidence, raw=evidence, finding_type="external_links")

        return finding(name, "info", "info", "No external resources detected")
    except Exception as e:
        return error_finding(name, e)


def check_protocol_relative_links(url: str) -> dict[str, Any]:
    name = "Protocol-relative links"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        links = PROTO_REL_RE.findall(r.text or "")
        out = []
        for l in sorted(set(links)):
            full = "http:" + l
            if _is_clearnet(full):
                out.append(l)
        if out:
            return finding(name, "warn", "medium", out, raw={"count": len(out)})
        return finding(name, "info", "info", "No protocol-relative external links")
    except Exception as e:
        return error_finding(name, e)


def check_cors(url: str) -> dict[str, Any]:
    name = "CORS headers"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        ac = {k: v for k, v in (r.headers.items() if r else []) if k.lower().startswith("access-control-")}
        if ac:
            return finding(name, "info", "low", [f"{k}: {v}" for k, v in ac.items()], raw=ac)
        return finding(name, "info", "info", "No CORS headers")
    except Exception as e:
        return error_finding(name, e)


def check_meta_redirects(url: str) -> dict[str, Any]:
    name = "Meta-refresh"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        p = html_extract(r.text or "")
        out = [x for x in _resolve_candidates(url, p.meta_refresh_targets) if _is_clearnet(x)]
        if out:
            return finding(name, "warn", "high", out, raw={"count": len(out)}, finding_type="deanon")
        return finding(name, "info", "info", "No meta-refresh to clearnet URLs")
    except Exception as e:
        return error_finding(name, e)


def check_robots_sitemap(url: str) -> dict[str, Any]:
    name = "Robots & sitemap"
    try:
        base = url.rstrip("/")
        out = []
        for path in ("/robots.txt", "/sitemap.xml"):
            res = fetch_with_policy(f"{base}{path}")
            if res.get("leak"):
                out.append(f"{path} redirect leak \u2192 {res['leak']}")
                continue
            r = res.get("response")
            if not r or r.status_code != 200 or not (r.content or b""):
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if _looks_like_html(r.content or b"", ct):
                continue
            text = r.text or ""
            if path.endswith("robots.txt"):
                lines = [l for l in text.splitlines() if l.lower().startswith(("disallow:", "sitemap:"))]
                if lines:
                    out.append("/robots.txt entries:\n" + "\n".join(lines))
            else:
                locs = re.findall(r"<loc>([^<]+)</loc>", text, re.IGNORECASE)
                if locs:
                    out.append("/sitemap.xml locs:\n" + "\n".join(locs[:100]))
        if out:
            return finding(name, "info", "low", out)
        return finding(name, "info", "info", "No robots.txt or sitemap.xml entries found")
    except Exception as e:
        return error_finding(name, e)


def check_form_actions(url: str) -> dict[str, Any]:
    name = "Form actions"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        p = html_extract(r.text or "")
        out = [x for x in _resolve_candidates(url, p.form_actions) if _is_clearnet(x)]
        if out:
            return finding(name, "warn", "high", out, raw={"count": len(out)}, finding_type="deanon")
        return finding(name, "info", "info", "No clearnet form actions")
    except Exception as e:
        return error_finding(name, e)


def check_websocket_endpoints(url: str) -> dict[str, Any]:
    name = "WebSocket endpoints"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        wss = re.findall(WEBSOCKET_RE, r.text or "")
        out = [ws for ws in sorted(set(wss)) if _is_clearnet(ws)]
        if out:
            return finding(name, "warn", "high", out, raw={"count": len(out)}, finding_type="deanon")
        return finding(name, "info", "info", "No clearnet WebSocket endpoints")
    except Exception as e:
        return error_finding(name, e)


def check_proxy_headers(url: str) -> dict[str, Any]:
    name = "Proxy headers"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        keys = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded"]
        found = [f"{k}: {r.headers[k]}" for k in keys if r and k in r.headers]
        if found:
            return finding(name, "warn", "high", found)
        return finding(name, "info", "info", "No proxy-related headers")
    except Exception as e:
        return error_finding(name, e)


def _looks_like_security_txt(body_text: str) -> bool:
    lines = [ln.strip() for ln in (body_text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return False
    has_contact = any(ln.lower().startswith("contact:") for ln in lines)
    has_expires = any(ln.lower().startswith("expires:") for ln in lines)
    first_ok = bool(SECURITYTXT_DIRECTIVE_RE.match(lines[0]))
    return first_ok and has_contact and has_expires


def _securitytxt_invalid_reason(r) -> Optional[str]:
    if not r:
        return "no response"
    ct = (r.headers.get("Content-Type", "") or "").lower()
    raw = r.content or b""
    if len(raw) == 0:
        return "empty body"
    if len(raw) > SECURITYTXT_MAX_BYTES:
        return f"too large ({len(raw)} bytes)"
    if _looks_like_html(raw, ct):
        return f"looks like HTML (Content-Type={ct or 'n/a'})"
    if ct and not (ct.startswith("text/") or "text" in ct or "charset=" in ct or "octet-stream" in ct):
        return f"suspicious Content-Type ({ct})"
    text = (r.text or "").strip()
    if not _looks_like_security_txt(text):
        return "missing required directives (need at least Contact and Expires)"
    return None


def _fetch_security_txt(base_url: str, path: str) -> dict[str, Any]:
    name = f"security.txt ({'root' if path == '/security.txt' else '.well-known'})"
    try:
        res = fetch_with_policy(f"{base_url.rstrip('/')}{path}")
        if res.get("leak"):
            return finding(name, "fail", "high", f"{path}: redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if not r:
            return finding(name, "warn", "low", f"{path}: no response")
        if r.status_code != 200:
            return finding(name, "info", "info", f"{path}: not found (HTTP {r.status_code})", raw={"status_code": r.status_code})
        reason = _securitytxt_invalid_reason(r)
        if reason:
            ct = r.headers.get("Content-Type", "") or "n/a"
            sample = (r.text or "")[:120].replace("\n", " ").strip()
            return finding(name, "warn", "medium", f"{path}: HTTP 200 but NOT valid security.txt ({reason}); Content-Type={ct}; sample='{sample}'")
        lines = [ln.strip() for ln in (r.text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
        return finding(name, "ok", "low", lines[:12], raw={"path": path})
    except Exception as e:
        return error_finding(name, e)


def check_captcha_leak(url: str) -> dict[str, Any]:
    name = "CAPTCHA leak"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if not r or r.status_code != 200:
            return finding(name, "info", "info", "No page to check for CAPTCHA leaks")
        text = (r.text or "").lower()
        leaks = set(re.findall(r'(?:src|href|fetch\()\s*["\'](https?://[^"\')]+captcha[^"\')]+)', text, re.IGNORECASE))
        for path in ("/lua/cap.lua", "/queue.html"):
            if path in text:
                for m in re.findall(r'["\']([^"\']+' + re.escape(path) + r')["\']', text):
                    full = m if m.startswith("http") else f"{url.rstrip('/')}{m}"
                    leaks.add(full)
        real = [u for u in sorted(leaks) if _is_clearnet(u)]
        if real:
            return finding(name, "warn", "high", real, raw={"count": len(real)}, finding_type="deanon")
        return finding(name, "info", "info", "No external CAPTCHA resources detected")
    except Exception as e:
        return error_finding(name, e)


def check_onion_location(url: str) -> dict[str, Any]:
    name = "Onion-Location header"
    try:
        r = request("GET", url, allow_redirects=False)
        val = r.headers.get("Onion-Location") or r.headers.get("onion-location")
        if val:
            return finding(name, "ok", "low", f"Onion-Location: {val}", raw={"value": val})
        return finding(name, "info", "info", "No Onion-Location header")
    except Exception as e:
        return error_finding(name, e)


def check_header_leaks(url: str) -> dict[str, Any]:
    name = "Header leaks"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        found = [f"{k}: {r.headers.get(k)}" for k in LEAK_HEADERS if r and k in r.headers]
        if found:
            return finding(name, "warn", "medium", found)
        return finding(name, "info", "info", "No obvious header leaks")
    except Exception as e:
        return error_finding(name, e)


def check_well_known(url: str) -> dict[str, Any]:
    name = "Well-known endpoints"
    try:
        hits = []
        for pth in WELL_KNOWN_PATHS:
            res = fetch_with_policy(f"{url.rstrip('/')}{pth}")
            if res.get("leak"):
                hits.append(f"{pth} -> redirect leak \u2192 {res['leak']}")
                continue
            r = res.get("response")
            if r and r.status_code == 200:
                ct = (r.headers.get("Content-Type", "") or "").lower()
                if _looks_like_html(r.content or b"", ct):
                    hits.append(f"{pth} -> 200 but looks like HTML (ct={ct or 'n/a'})")
                else:
                    hits.append(f"{pth} -> 200 ({ct or 'n/a'})")
        if hits:
            return finding(name, "info", "low", hits)
        return finding(name, "info", "info", "No .well-known endpoints found")
    except Exception as e:
        return error_finding(name, e)



def check_http_availability(url: str) -> dict[str, Any]:
    name = "HTTP origin availability"
    res = fetch_with_policy(url, timeout=min(cfg.http_timeout, 10.0), max_hops=2, verify=False)
    r = res.get("response")
    if r is not None:
        return finding(name, "ok", "info", [
            f"Selected origin: {url}",
            f"HTTP status: {r.status_code}",
            f"Final URL: {res.get('final_url', url)}",
        ], raw=res, finding_type="network")
    return finding(name, "warn", "low", f"No HTTP response ({res.get('error_kind', 'unknown')}: {res.get('error', 'unknown error')})", raw=res, finding_type="network")




def check_https_tls(url: str) -> dict[str, Any]:
    name = "HTTPS/TLS sanity"
    host = urlparse(url).hostname or ""
    if not host:
        return finding(name, "error", "info", "Invalid host")

    try:
        raw = _make_socks_socket(host, 443, cfg.tls_timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(raw, server_hostname=host)

        der = ssock.getpeercert(binary_form=True)
        cipher = ssock.cipher()
        version = ssock.version()
        ssock.close()

        evidence = [
            "HTTPS/TLS reachable",
            f"TLS version: {version or 'n/a'}",
            f"Cipher: {cipher[0] if cipher else 'n/a'}",
        ]
        raw_out = {"tls_version": version, "cipher": cipher}

        if der:
            cert_sha256 = hashlib.sha256(der).hexdigest()
            raw_out["cert_sha256"] = cert_sha256
            evidence.append(f"Certificate SHA256: {cert_sha256}")

            if x509 is not None:
                cert = x509.load_der_x509_certificate(der, default_backend())
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
                not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)

                raw_out.update({
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                })

                evidence += [
                    f"Subject: {subject}",
                    f"Issuer: {issuer}",
                    f"Valid: {not_before} -> {not_after}",
                ]
            else:
                evidence.append("Certificate metadata parser unavailable; install cryptography for subject/issuer/validity")

            return finding(name, "ok", "low", evidence, raw=raw_out, finding_type="network")

        return finding(
            name,
            "warn",
            "medium",
            "HTTPS/TLS reachable on 443 but peer certificate was not returned",
            raw=raw_out,
            finding_type="network",
        )

    except Exception as e:
        info = classify_network_error(e)
        return finding(
            name,
            "info",
            "info",
            f"HTTPS/TLS not reachable on 443 ({info['kind']}): {info['error']}",
            raw=info,
            finding_type="network",
        )



def check_csp_related(url: str) -> dict[str, Any]:
    name = "CSP / Report-To / NEL / Link"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")

        r = res.get("response")
        if not r:
            return finding(name, "warn", "low", "No response", raw=res)

        policy_external = []
        reporting_external = []
        link_header_external = []

        for hdr in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
            if hdr not in r.headers:
                continue
            val = r.headers.get(hdr, "")
            urls = re.findall(r"https?://[^\s;,\">]+", val, re.IGNORECASE)
            clear = [u for u in urls if _is_clearnet(u)]
            if clear:
                policy_external.append({hdr: sorted(set(clear))})

        for hdr in ("Report-To", "NEL"):
            if hdr not in r.headers:
                continue
            val = r.headers.get(hdr, "")
            urls = re.findall(r"https?://[^\s;,\">]+", val, re.IGNORECASE)
            clear = [u for u in urls if _is_clearnet(u)]
            if clear:
                reporting_external.append({hdr: sorted(set(clear))})

        if "Link" in r.headers:
            val = r.headers.get("Link", "")
            urls = re.findall(r"https?://[^\s;,\">]+", val, re.IGNORECASE)
            clear = [u for u in urls if _is_clearnet(u)]
            if clear:
                link_header_external.append({"Link": sorted(set(clear))})

        evidence = {
            "policy_allows_external": policy_external,
            "external_reporting_endpoints": reporting_external,
            "external_link_headers": link_header_external,
        }

        if reporting_external or link_header_external:
            return finding(name, "warn", "high", evidence, raw=evidence, finding_type="deanon")

        if policy_external:
            return finding(name, "warn", "medium", evidence, raw=evidence, finding_type="policy")

        return finding(name, "info", "info", "No obvious clearnet leakage in CSP/Report-To/NEL/Link headers")
    except Exception as e:
        return error_finding(name, e)


def check_meta_and_link_leaks(url: str) -> dict[str, Any]:
    name = "Canonical / alternate / OG / Twitter / preload"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        p = html_extract(r.text or "")
        buckets = {
            "canonical": _resolve_candidates(url, p.canonical_urls),
            "alternate": _resolve_candidates(url, p.alternate_urls),
            "preconnect": _resolve_candidates(url, p.preconnect_urls),
            "prefetch": _resolve_candidates(url, p.prefetch_urls),
            "preload": _resolve_candidates(url, p.preload_urls),
            "og": _resolve_candidates(url, p.og_urls),
            "twitter": _resolve_candidates(url, p.twitter_urls),
        }
        hits = []
        for k, vals in buckets.items():
            clear = [v for v in vals if _is_clearnet(v)]
            if clear:
                hits.append(f"{k}: " + " | ".join(clear[:20]))
        if hits:
            return finding(name, "warn", "high", hits, finding_type="deanon")
        return finding(name, "info", "info", "No clearnet leaks in canonical/alternate/OG/Twitter/pre* metadata")
    except Exception as e:
        return error_finding(name, e)


def analyze_set_cookie(url: str) -> dict[str, Any]:
    name = "Set-Cookie analysis"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if not r:
            return finding(name, "warn", "low", "No response")
        cookies = []
        raw_headers = getattr(r.raw, "headers", None)
        if raw_headers and hasattr(raw_headers, "getlist"):
            cookies = raw_headers.getlist("Set-Cookie")
        if not cookies:
            val = r.headers.get("Set-Cookie")
            if val:
                cookies = [val]
        if not cookies:
            return finding(name, "info", "info", "No Set-Cookie headers")

        findings = []
        for sc in cookies:
            low = sc.lower()
            issues = []
            if "secure" not in low:
                issues.append("missing Secure")
            if "httponly" not in low:
                issues.append("missing HttpOnly")
            if "samesite=" not in low:
                issues.append("missing SameSite")
            m = re.search(r";\s*domain=([^;]+)", sc, re.IGNORECASE)
            if m:
                dom = m.group(1).strip()
                if not dom.endswith(".onion"):
                    issues.append(f"Domain={dom}")
            label = sc.split(";", 1)[0]
            findings.append(f"{label} -> " + (", ".join(issues) if issues else "OK"))
        risk = "medium" if any("missing Secure" in x or "Domain=" in x for x in findings) else "low"
        status = "warn" if any("-> OK" not in x for x in findings) else "ok"
        return finding(name, status, risk, findings, raw={"count": len(cookies)})
    except Exception as e:
        return error_finding(name, e)



def normalize_obfuscated_email(value: str) -> Optional[str]:
    raw = (value or "").strip()
    raw = re.sub(r"^mailto:", "", raw, flags=re.IGNORECASE)
    raw = raw.split("?", 1)[0].strip()
    if not raw:
        return None

    candidate = raw
    replacements = [
        (r"\s*(?:\(|\[|\{)\s*at\s*(?:\)|\]|\})\s*", "@"),
        (r"\s+at\s+", "@"),
        (r"\s*(?:\(|\[|\{)\s*dot\s*(?:\)|\]|\})\s*", "."),
        (r"\s+dot\s+", "."),
    ]

    for pattern, repl in replacements:
        candidate = re.sub(pattern, repl, candidate, flags=re.IGNORECASE)

    candidate = candidate.replace(" ", "")
    if EMAIL_RE.fullmatch(candidate):
        return candidate

    return None


def extract_obfuscated_emails(text: str) -> list[str]:
    found = set()

    for m in MAILTO_RE.finditer(text or ""):
        v = normalize_obfuscated_email(m.group(1))
        if v:
            found.add(v)

    for m in OBF_EMAIL_RE.finditer(text or ""):
        raw = m.group(0)
        v = normalize_obfuscated_email(raw)
        if v:
            found.add(v)

    return sorted(found)


def split_placeholder_emails(emails: set[str]) -> tuple[set[str], set[str]]:
    real = set()
    placeholders = set()

    for email in emails:
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if domain in PLACEHOLDER_EMAIL_DOMAINS:
            placeholders.add(email)
        else:
            real.add(email)

    return real, placeholders




def extract_indicators_from_text(text: str) -> dict[str, list[str]]:
    t = text or ""

    normal_emails = set(EMAIL_RE.findall(t))
    obfuscated_emails = set(extract_obfuscated_emails(t))
    all_emails = normal_emails | obfuscated_emails
    real_emails, placeholder_emails = split_placeholder_emails(all_emails)

    return {
        "emails": sorted(real_emails),
        "obfuscated_emails": sorted(obfuscated_emails - placeholder_emails),
        "placeholder_emails": sorted(placeholder_emails),
        "btc": sorted(set(BTC_RE.findall(t))),
        "eth": sorted(set(ETH_RE.findall(t))),
        "xmr": sorted(set(XMR_RE.findall(t))),
    }



def indicators_from_urls(urls: list[str]) -> dict[str, list[str]]:
    agg = {
        "emails": set(),
        "obfuscated_emails": set(),
        "placeholder_emails": set(),
        "btc": set(),
        "eth": set(),
        "xmr": set(),
    }

    for u in urls:
        try:
            r = fetch_with_policy(u).get("response")
            if not r or r.status_code != 200:
                continue

            ct = (r.headers.get("Content-Type", "") or "").lower()
            if "html" not in ct and "xhtml" not in ct:
                continue

            ind = extract_indicators_from_text(r.text or "")
            for k in agg:
                agg[k].update(ind.get(k, []))
        except Exception:
            continue

    return {k: sorted(v) for k, v in agg.items()}


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
    return full.split("#", 1)[0]


def _hash_html(text: str) -> str:
    t = re.sub(r"\s+", " ", (text or "").strip().lower())
    return hashlib.sha256(t.encode("utf-8", errors="ignore")).hexdigest()


def _get_home_fingerprint(base_url: str) -> Optional[str]:
    try:
        r = fetch_with_policy(base_url + "/").get("response")
        if not r or r.status_code != 200:
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
    if looks_like_soft404(r, soft404_baseline):
        return True
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if r.status_code == 200 and "html" in ct and home_fp:
            if _hash_html(r.text or "") == home_fp:
                return True
    except Exception:
        pass
    return False


def crawl_links(base_url: str, max_urls: int = 80, depth: int = 1) -> list[str]:
    from collections import deque
    base = base_url.rstrip("/")
    home_fp = _get_home_fingerprint(base)
    soft404_baseline = get_soft404_baseline(base)
    start_urls = [base + "/", base + "/robots.txt", base + "/sitemap.xml"]

    q = deque((u, 0) for u in start_urls)
    seen = set()
    out = []

    while q and len(out) < max_urls:
        current, d = q.popleft()
        if current in seen:
            continue
        seen.add(current)
        if not same_onion_host(base, current):
            continue
        if ASSET_EXT_SKIP.search(urlparse(current).path or ""):
            continue

        try:
            result = fetch_with_policy(current)
            if result.get("leak"):
                continue
            r = result.get("response")
            if not r:
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if r.status_code != 200 or ("html" not in ct and "xhtml" not in ct):
                continue
            is_homepage = current.rstrip("/") == base.rstrip("/")
            if not is_homepage and _looks_like_index_redirect_or_soft404(r, soft404_baseline, home_fp):
                continue
            out.append(current)
            if d >= depth:
                continue

            parser = html_extract(r.text or "")
            hrefs = parser.anchor_hrefs + [href for _, href in parser.link_hrefs] + parser.script_srcs + parser.img_srcs
            for href in hrefs:
                full = _norm_url(base, href)
                if not full or not same_onion_host(base, full):
                    continue
                if full not in seen:
                    q.append((full, d + 1))
        except Exception:
            continue
    return out


def crawl_finding(url: str) -> tuple[dict[str, Any], list[str]]:
    name = "Crawl links"
    if cfg.no_crawl:
        return finding(name, "info", "info", "Skipped (--no-crawl)"), []
    try:
        urls = crawl_links(url, max_urls=cfg.crawl_max_urls, depth=cfg.crawl_depth)
        return finding(name, "ok", "info", f"Collected {len(urls)} URLs (depth={cfg.crawl_depth}, max={cfg.crawl_max_urls})", raw={"count": len(urls), "urls": urls[:100]}), urls
    except Exception as e:
        return error_finding(name, e), []


def indicator_finding(urls: list[str]) -> dict[str, Any]:
    name = "Indicators (emails/crypto)"
    if not urls:
        return finding(name, "info", "info", "No crawled URLs to analyze")
    try:
        ind = indicators_from_urls(urls)
        return finding(name, "info", "low", ind if any(ind.values()) else "No indicators found", raw=ind)
    except Exception as e:
        return error_finding(name, e)


def render_text_evidence(ev: Any) -> str:
    if isinstance(ev, list):
        return " | ".join(str(x) for x in ev)
    if isinstance(ev, dict):
        return json.dumps(ev, ensure_ascii=False)
    return str(ev)


def render_txt_report(target_url: str, results: list[dict[str, Any]]) -> str:
    lines = [ASCII_LOGO.strip("\n"), "", f"Target: {target_url}", ""]
    for item in results:
        lines.append(f"== {item['name']} ==")
        lines.append(f"status={item['status']} risk={item['risk']} type={item['finding_type']}")
        lines.append(render_text_evidence(item["evidence"]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"





def _style_status(status: str) -> str:
    return {
        "ok": "green",
        "info": "bright_blue",
        "warn": "orange1",
        "fail": "red",
        "error": "bold red",
    }.get((status or "info").lower(), "white")


def _style_risk(risk: str) -> str:
    return {
        "info": "bright_blue",
        "low": "yellow",
        "medium": "orange1",
        "high": "red",
        "critical": "bold red",
    }.get((risk or "info").lower(), "white")


def _style_type(finding_type: str) -> str:
    return {
        "info": "bright_blue",
        "network": "cyan",
        "internal": "dim red",
        "dependency": "magenta",
        "external_links": "cyan",
        "deanon": "bold red",
        "policy": "yellow",
        "leak": "orange1",
    }.get((finding_type or "info").lower(), "white")


def _cell(value: Any, style: str) -> str:
    text = str(value)
    return f"[{style}]{text}[/{style}]"


def status_cell(status: str) -> str:
    return _cell(status, _style_status(status))


def risk_cell(risk: str) -> str:
    return _cell(risk, _style_risk(risk))


def type_cell(finding_type: str) -> str:
    return _cell(finding_type, _style_type(finding_type))


def run_step(idx: int, total: int, desc: str, fn, json_mode: bool) -> dict[str, Any]:
    if json_mode:
        try:
            return fn()
        except Exception as e:
            return error_finding(desc, e)

    # Only the live status line is shown while the check is running.
    # After the context exits, Rich clears it and we print one final complete line.
    with console.status(f"[bright_blue]{idx}/{total} running: {desc}[/bright_blue]", spinner="dots"):
        try:
            out = fn()
        except Exception as e:
            out = error_finding(desc, e)

        if cfg.sleep > 0:
            time.sleep(cfg.sleep)

    name = out.get("name", desc)
    console.print(f"[green]\u2713 {idx}/{total} complete: {name}[/green]")
    return out

def show_help() -> None:
    console.print(ASCII_LOGO)
    console.print("Lightweight CLI for basic Tor hidden-service (.onion) security checks\n")
    console.print("usage:")
    console.print("  onionscout [options] -u URL\n")


class CustomParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        super().__init__(add_help=False, **kwargs)

    def print_usage(self, file=None):
        return None

    def error(self, message):
        console.print(ASCII_LOGO)
        console.print(f"[red]Error: {message}[/red]\n")
        self.print_help()
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = CustomParser(description="CLI tool for Tor hidden-service (.onion) security checks")
    parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
    parser.add_argument("-u", "--url", required=True, help=".onion URL to scan (e.g. abcdef.onion or abcdef.onion:8080)")
    parser.add_argument("--http-timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10.0)")
    parser.add_argument("--ssh-timeout", type=float, default=10.0, help="SSH timeout in seconds (default: 10.0)")
    parser.add_argument("--tls-timeout", type=float, default=12.0, help="TLS timeout in seconds (default: 12.0)")
    parser.add_argument("-s", "--sleep", type=float, default=1.0, help="seconds between checks (default: 1.0)")
    parser.add_argument("--socks", default="127.0.0.1:9050", help="Tor SOCKS5h proxy (default: 127.0.0.1:9050)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port for fingerprint check (default: 22)")
    parser.add_argument("--skip-tor-check", action="store_true", help="do not call check.torproject.org")
    parser.add_argument("--json", action="store_true", help="output JSON instead of a table")
    parser.add_argument("--cookie", help="raw Cookie header, e.g. 'a=b; c=d'")
    parser.add_argument("-o", "--output", help="write report to file (JSON if --json, else TXT)")
    parser.add_argument("--insecure-https", action="store_true", help="disable TLS verification for HTTPS HTTP requests")
    parser.add_argument("--scheme", choices=["auto", "http", "https"], default="auto", help="origin scheme mode (default: auto)")
    parser.add_argument("--retries", type=int, default=2, help="network retries for transient onion errors (default: 2)")
    parser.add_argument("--workers", type=int, default=4, help="parallel workers for crawler page fetches (default: 4)")
    parser.add_argument("--no-crawl", action="store_true", help="disable crawler-based checks")
    parser.add_argument("--max-urls", type=int, default=80, help="crawler max URLs (default: 80)")
    parser.add_argument("--depth", type=int, default=1, help="crawler depth (default: 1)")
    return parser


def main() -> None:
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args()

    cfg.http_timeout = args.http_timeout
    cfg.ssh_timeout = args.ssh_timeout
    cfg.tls_timeout = args.tls_timeout
    cfg.sleep = args.sleep
    cfg.insecure_https = args.insecure_https
    cfg.no_crawl = args.no_crawl
    cfg.crawl_max_urls = max(1, args.max_urls)
    cfg.crawl_depth = max(0, args.depth)
    cfg.scheme = args.scheme
    cfg.retries = max(0, args.retries)
    cfg.workers = max(1, args.workers)

    socks_host, socks_port = parse_socks(args.socks)
    cfg.socks_host, cfg.socks_port = socks_host, socks_port
    configure_tor_proxy(socks_host, socks_port)

    if args.cookie:
        set_cookie_header(args.cookie)

    try:
        target_input = normalize_url(args.url)
    except Exception as e:
        console.print(ASCII_LOGO)
        console.print(f"[red]Error: {e}[/red]\n")
        parser.print_help()
        sys.exit(1)

    base_url, origin_info = choose_working_origin(target_input, cfg.scheme)

    if not args.json:
        console.print(ASCII_LOGO)
        if origin_info.get("note"):
            console.print(f"[yellow]Origin selection: {origin_info.get('note')}[/yellow]")

    crawled_urls: list[str] = []

    def run_crawl_step() -> dict[str, Any]:
        nonlocal crawled_urls
        crawl_res, urls = crawl_finding(base_url)
        crawled_urls = urls
        return crawl_res

    def run_indicator_step() -> dict[str, Any]:
        return indicator_finding(crawled_urls)

    tasks: list[tuple[str, Any]] = []

    if not args.skip_tor_check:
        tasks.append(("SOCKS/Tor connectivity check", lambda: check_tor_proxy()))
    else:
        tasks.append((
            "SOCKS/Tor connectivity check",
            lambda: finding("SOCKS/Tor connectivity check", "info", "info", "Skipped (--skip-tor-check)")
        ))

    tasks += [
        ("Cookie provided", lambda: check_cookie_present(args.cookie)),
        ("Origin selection", lambda: finding("Origin selection", "info", "info", origin_info)),
        ("HTTP origin availability", lambda: check_http_availability(base_url)),
        ("Detect server", lambda: detect_server(base_url)),
        ("HTTPS/TLS sanity", lambda: check_https_tls(base_url)),
        ("Detect favicon", lambda: check_favicon(base_url)),
        ("Favicon in HTML", lambda: check_favicon_in_html(base_url)),
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
        ("security.txt (root)", lambda: _fetch_security_txt(base_url, "/security.txt")),
        ("security.txt (.well-known)", lambda: _fetch_security_txt(base_url, "/.well-known/security.txt")),
        ("CAPTCHA leak", lambda: check_captcha_leak(base_url)),
        ("CSP / Report-To / NEL / Link", lambda: check_csp_related(base_url)),
        ("Canonical / alternate / OG / Twitter / preload", lambda: check_meta_and_link_leaks(base_url)),
        ("Set-Cookie analysis", lambda: analyze_set_cookie(base_url)),
        ("Crawl links", run_crawl_step),
        ("Indicators (emails/crypto)", run_indicator_step),
    ]

    total = len(tasks)
    results = []

    for idx, (desc, fn) in enumerate(tasks, start=1):
        out = run_step(idx, total, desc, fn, args.json)
        results.append(out)

    payload = {
        "tool": "onionscout",
        "version": "0.1.3",
        "target": base_url,
        "config": {
            "http_timeout": cfg.http_timeout,
            "ssh_timeout": cfg.ssh_timeout,
            "tls_timeout": cfg.tls_timeout,
            "sleep": cfg.sleep,
            "socks": f"{cfg.socks_host}:{cfg.socks_port}",
            "insecure_https": cfg.insecure_https,
            "no_crawl": cfg.no_crawl,
            "max_urls": cfg.crawl_max_urls,
            "depth": cfg.crawl_depth,
            "scheme": cfg.scheme,
            "retries": cfg.retries,
            "workers": cfg.workers,
            "html_parser": "selectolax" if SelectolaxHTMLParser is not None else "stdlib",
            "origin_selection": origin_info,
        },
        "results": results,
    }

    if args.json:
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
    table.add_column("Status")
    table.add_column("Risk")
    table.add_column("Type")
    table.add_column("Evidence")
    for item in results:
        table.add_row(
            item["name"],
            status_cell(item["status"]),
            risk_cell(item["risk"]),
            type_cell(item["finding_type"]),
            render_text_evidence(item["evidence"]),
        )
    console.print(table)

    if args.output:
        txt = render_txt_report(base_url, results)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(txt)
        console.print(f"\n[cyan]Saved report to: {args.output}[/cyan]")


if __name__ == "__main__":
    main()
