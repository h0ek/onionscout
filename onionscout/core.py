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
import threading
from difflib import SequenceMatcher
from html import escape
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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
v0.4.7
"""

VERSION = "0.4.7"

console = Console()
_REDIRECTS = {301, 302, 303, 307, 308}
SECURITYTXT_MAX_BYTES = 200_000
DOCUMENT_METADATA_MAX_BYTES = 1_500_000
HTML_REPORT_MAX_RAW_CHARS = 20_000
CORS_PROBE_ORIGIN = "http://corsprobeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"


@dataclass
class Config:
    http_timeout: float = 10.0
    ssh_timeout: float = 10.0
    tls_timeout: float = 12.0
    sleep: float = 1.0
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    tor_mode: str = "socks"
    insecure_https: bool = False
    auto_insecure_https: bool = True
    auto_insecure_https_reason: Optional[str] = None
    no_crawl: bool = False
    crawl_max_urls: int = 80
    crawl_depth: int = 1
    scheme: str = "auto"
    retries: int = 2
    workers: int = 4
    cookie_header: Optional[str] = None
    target_host: str = ""
    clearnet_url: Optional[str] = None
    profile: str = "safe"
    target_port: Optional[int] = None
    max_body_bytes: int = 2_000_000
    max_requests: int = 350
    max_duration: float = 900.0
    requests_made: int = 0
    response_cache: Optional[dict] = None
    soft404_cache: Optional[dict] = None
    started_at: float = 0.0


cfg = Config()

session = requests.Session()
session.trust_env = False
_request_lock = threading.Lock()
_last_request_at = 0.0
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
})


def rebuild_retry_adapter() -> None:
    adapter = HTTPAdapter(max_retries=Retry(total=0, redirect=0, status=0, connect=0, read=0))
    session.mount("http://", adapter)
    session.mount("https://", adapter)


rebuild_retry_adapter()


def configure_tor_proxy(host: str, port: int) -> None:
    if not host or not 1 <= port <= 65535:
        raise ValueError("Invalid SOCKS proxy")
    proxy = f"socks5h://{host}:{port}"
    cfg.tor_mode = "socks"
    session.trust_env = False
    session.proxies = {"http": proxy, "https": proxy}


def configure_transparent_tor() -> None:
    cfg.tor_mode = "transparent"
    session.trust_env = False
    session.proxies = {}


def preflight_tor_socks(host: str, port: int, timeout: float = 5.0) -> None:
    if not host or not 1 <= port <= 65535:
        raise ValueError("Invalid SOCKS proxy")
    timeout = max(0.1, min(float(timeout), 10.0))
    endpoint = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            reply = b""
            while len(reply) < 2:
                chunk = sock.recv(2 - len(reply))
                if not chunk:
                    break
                reply += chunk
    except OSError as e:
        raise RuntimeError(f"Tor SOCKS proxy {endpoint} is unavailable: {e}") from e
    if len(reply) != 2:
        raise RuntimeError(f"Tor SOCKS proxy {endpoint} closed during SOCKS5 negotiation")
    if reply[0] != 0x05:
        raise RuntimeError(f"Tor SOCKS proxy {endpoint} does not speak SOCKS5")
    if reply[1] == 0xFF:
        raise RuntimeError(f"Tor SOCKS proxy {endpoint} rejected the supported SOCKS5 authentication method")
    if reply[1] != 0x00:
        raise RuntimeError(f"Tor SOCKS proxy {endpoint} requires unsupported SOCKS5 authentication")


def set_cookie_header(cookie_str: str) -> None:
    cfg.cookie_header = cookie_str.strip()


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
        self.base_href: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "base" and a.get("href") and self.base_href is None:
            self.base_href = a["href"]

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

        base_nodes = tree.css("base[href]")
        if base_nodes:
            out.base_href = base_nodes[0].attributes.get("href")

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
URL_LITERAL_RE = re.compile(r'(?P<url>(?:https?|wss?)://[^\s"\'<>)]+|//[a-z0-9.-]+\.[a-z]{2,}[^\s"\'<>)]*)', re.IGNORECASE)
SOURCE_MAP_RE = re.compile(r'sourceMappingURL\s*=\s*([^\s*]+)', re.IGNORECASE)
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
ONION_V3_HOST_RE = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)

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

SECURITY_HEADER_EXPECTATIONS = {
    "Content-Security-Policy": "helps reduce script/content injection and unwanted external dependencies",
    "X-Content-Type-Options": "should normally be nosniff",
    "Referrer-Policy": "reduces accidental URL/referrer leakage",
    "X-Frame-Options": "or use CSP frame-ancestors",
    "Permissions-Policy": "limits browser feature exposure",
    "Cross-Origin-Opener-Policy": "browser isolation hardening",
    "Cross-Origin-Resource-Policy": "cross-origin resource isolation",
}

HTTP_METHODS_TO_CHECK = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "PROPFIND", "MKCOL"]
DANGEROUS_HTTP_METHODS = {"TRACE", "PUT", "DELETE", "PATCH", "PROPFIND", "MKCOL"}

SENSITIVE_PATHS = [
    "/info.php", "/phpinfo.php", "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/requires",
    "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/config.php", "/config.json", "/config.yml", "/configuration.php",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json", "/yarn.lock",
    "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/backup.sql", "/db.sql", "/dump.sql",
    "/debug", "/admin", "/backup", "/backups", "/secret", "/server-status", "/server-info",
]

DIRECTORY_LISTING_PATHS = ["/", "/uploads/", "/files/", "/static/", "/media/", "/backup/", "/backups/", "/data/", "/logs/"]
DIRECTORY_LISTING_RE = re.compile(
    r"(<title>\s*Index of\s*/|Index of /|Parent Directory|Directory listing for /|\[ICO\].*?\[DIR\])",
    re.IGNORECASE | re.DOTALL,
)

JS_SCAN_MAX_FILES = 10
JS_SCAN_MAX_BYTES = 300_000
IMAGE_METADATA_MAX_IMAGES = 8
IMAGE_METADATA_MAX_BYTES = 2_000_000
IMAGE_EXT_RE = re.compile(r"\.(?:jpe?g|png|webp|tiff?)$", re.IGNORECASE)
IMAGE_METADATA_MARKERS = [
    b"Exif\x00\x00", b"http://", b"https://", b"GPS", b"GPSLatitude", b"GPSLongitude",
    b"Software", b"CreatorTool", b"ImageDescription", b"Artist", b"Copyright",
    b"Adobe", b"Photoshop", b"GIMP", b"Lightroom", b"Make", b"Model", b"xmpmeta",
]

DOCUMENT_EXT_RE = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|odt|ods|odp|rtf|txt|csv|zip)(?:$|[?#])", re.IGNORECASE)
DOCUMENT_METADATA_RE = re.compile(
    r"(?i)(?:Author|Creator|Producer|Company|LastModifiedBy|Manager|Template|Application|CreationDate|ModDate|dc:creator|cp:lastModifiedBy)\s*[:=>\"']{1,6}\s*([^<\r\n\x00]{1,120})"
)
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\r\n\x00<>:\"|?*]{1,80}\\){1,8}[^\\\r\n\x00<>:\"|?*]{1,120}")
LINUX_PATH_RE = re.compile(r"/(?:home|var|srv|opt|etc|usr/local|app|www)/(?:[^\s\r\n\x00<>\"']{1,80}/){0,8}[^\s\r\n\x00<>\"']{1,120}")

BACKUP_ARCHIVE_PATHS_SAFE = [
    "/backup.zip", "/backup.tar", "/backup.tar.gz", "/backup.tgz", "/backups.zip", "/site.zip",
    "/site.tar.gz", "/www.zip", "/www.tar.gz", "/public.zip", "/public_html.zip", "/html.zip",
    "/app.zip", "/source.zip", "/src.zip", "/db.sql", "/database.sql", "/dump.sql", "/prod.sql",
    "/backup.sql", "/database.sqlite", "/db.sqlite", "/config.php.bak", "/index.php.bak", "/.env.bak",
]
BACKUP_ARCHIVE_PATHS_EXTENDED = BACKUP_ARCHIVE_PATHS_SAFE + [
    "/old.zip", "/old.tar.gz", "/new.zip", "/latest.zip", "/release.zip", "/deploy.zip", "/htdocs.zip",
    "/web.zip", "/root.zip", "/var_www.zip", "/wwwroot.zip", "/mysql.sql", "/postgres.sql",
    "/users.sql", "/data.sql", "/app.sql", "/config.php~", "/index.php~", "/settings.php.bak",
]
ERROR_PAGE_PATTERNS = [
    ("Django debug page", re.compile(r"Django(?: version)? .*?Exception Type:|Traceback .*?Django", re.IGNORECASE | re.DOTALL)),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|Traceback \(most recent call last\).*?werkzeug", re.IGNORECASE | re.DOTALL)),
    ("Laravel debug page", re.compile(r"Whoops!|Laravel.*?(?:Stack trace|Exception)", re.IGNORECASE | re.DOTALL)),
    ("Symfony debug page", re.compile(r"Symfony.*?Exception|Stack Trace.*?Symfony", re.IGNORECASE | re.DOTALL)),
    ("Rails error page", re.compile(r"Ruby on Rails|Action Controller: Exception caught|ActiveRecord::", re.IGNORECASE)),
    ("Express stack trace", re.compile(r"Error: .*?\n\s+at .*?\(.*?\.js:\d+:\d+\)", re.IGNORECASE | re.DOTALL)),
    ("PHP warning/error", re.compile(r"(?:PHP )?(?:Fatal error|Warning|Notice|Parse error):", re.IGNORECASE)),
    ("Java stack trace", re.compile(r"(?:java\.|javax\.|org\.apache\.).*?Exception", re.IGNORECASE | re.DOTALL)),
    ("Tomcat error page", re.compile(r"Apache Tomcat/|HTTP Status \d{3} –", re.IGNORECASE)),
    ("nginx default error page", re.compile(r"<center>nginx(?:/[^<]+)?</center>", re.IGNORECASE)),
    ("Apache default error page", re.compile(r"Apache(?:/[^\s<]+)? Server at .*? Port \d+", re.IGNORECASE | re.DOTALL)),
]

CHECK_KEY_ALIASES = {
    "target": "target-onion",
    "tor": "tor",
    "origin": "origin-selection",
    "availability": "http-availability",
    "server": "detect-server",
    "tls": "https-tls",
    "headers": "security-headers",
    "security": "security-headers",
    "methods": "http-methods",
    "files": "files-paths",
    "paths": "files-paths",
    "backup": "backup-archives",
    "backups": "backup-archives",
    "archives": "backup-archives",
    "listing": "directory-listing",
    "robots": "robots-sitemap",
    "sitemap": "robots-sitemap",
    "forms": "form-actions",
    "websocket": "websockets",
    "websockets": "websockets",
    "javascript": "js-leaks",
    "js": "js-leaks",
    "images": "image-metadata",
    "image": "image-metadata",
    "documents": "document-metadata",
    "docs": "document-metadata",
    "metadata": "metadata-leaks",
    "og": "metadata-leaks",
    "rss": "metadata-leaks",
    "jsonld": "metadata-leaks",
    "json-ld": "metadata-leaks",
    "cookies": "set-cookie",
    "cookie": "cookie-provided",
    "securitytxt": "securitytxt-well-known",
    "security.txt": "securitytxt-well-known",
    "errors": "error-pages",
    "error-pages": "error-pages",
    "fingerprinting": "fingerprinting-js",
    "fingerprint-js": "fingerprinting-js",
    "browser-fingerprinting": "fingerprinting-js",
    "api": "api-exposure",
    "swagger": "api-exposure",
    "openapi": "api-exposure",
    "graphql": "api-exposure",
    "cloud": "infrastructure",
    "infra": "infrastructure",
    "infrastructure": "infrastructure",
    "analytics": "analytics-ids",
    "trackers": "analytics-ids",
    "iframe": "iframes-js",
    "iframes": "iframes-js",
    "obfuscation": "iframes-js",
}

BASIC_CHECK_KEYS = {
    "tor", "cookie-provided", "target-onion", "origin-selection", "http-availability", "detect-server",
    "https-tls", "onion-location", "header-leaks", "security-headers", "cors", "robots-sitemap",
    "securitytxt-well-known", "csp-related", "metadata-leaks", "set-cookie",
}

SAFE_CHECK_KEYS = {
    "tor", "cookie-provided", "target-onion", "origin-selection", "http-availability", "detect-server",
    "https-tls", "favicon", "favicon-html", "etag", "onion-location", "header-leaks", "security-headers",
    "ssh", "comments", "status-pages", "http-methods", "files-paths", "backup-archives",
    "directory-listing", "well-known", "external-resources", "protocol-relative", "cors", "meta-refresh",
    "robots-sitemap", "form-actions", "websockets", "js-leaks", "image-metadata", "proxy-headers",
    "securitytxt-root", "securitytxt-well-known", "captcha", "csp-related", "metadata-leaks",
    "set-cookie", "error-pages", "crawl", "document-metadata", "indicators",
    "fingerprinting-js", "api-exposure", "infrastructure", "analytics-ids", "iframes-js",
}

PROFILE_CHECK_KEYS = {
    "basic": BASIC_CHECK_KEYS,
    "safe": SAFE_CHECK_KEYS,
    "extended": SAFE_CHECK_KEYS,
}


def validate_onion_v3(address: str) -> bool:
    if not re.fullmatch(r"[a-z2-7]{56}", address or ""):
        return False
    try:
        packed = base64.b32decode(address.upper())
    except (ValueError, base64.binascii.Error):
        return False
    key, checksum, version = packed[:32], packed[32:34], packed[34:35]
    return version == b"\x03" and hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2] == checksum


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    if not host.endswith(".onion"):
        raise ValueError("Provide a valid .onion URL")
    address = host[:-6].split(".")[-1]
    if not validate_onion_v3(address):
        raise ValueError("Invalid onion v3 address or checksum")
    if p.username or p.password or p.fragment or p.query or p.port == 0:
        raise ValueError("Target must not contain credentials, query or fragment")
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
    try:
        res = fetch_with_policy(base_url, timeout=timeout, max_hops=2)
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
        selected = (probe.get("final_url") or candidate) if probe.get("ok") else candidate
        if not is_target_onion_url(selected) or not _same_target_port(selected):
            selected = candidate
        if urlparse(selected).path:
            selected = _base_for_scheme(urlparse(selected), urlparse(selected).scheme)
        return selected.rstrip("/"), {"mode": scheme_mode, "selected": selected.rstrip("/"), "attempts": attempts}

    candidates = []
    preferred = _base_from_parsed(p)
    candidates.append(preferred)

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

    effective_https = [a for a in ok_attempts if a.get("final_scheme") == "https"]
    if effective_https:
        chosen = effective_https[0]
    else:
        chosen = ok_attempts[0]

    selected = chosen.get("final_url") or chosen.get("url")
    if not is_target_onion_url(selected) or not _same_target_port(selected):
        selected = chosen.get("url")
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


def is_target_onion_url(url: str) -> bool:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return p.scheme in {"http", "https"} and host.endswith(".onion") and bool(cfg.target_host and host == cfg.target_host)


def _tls_auto_insecure_reason(error: Exception) -> Optional[str]:
    text = str(error).lower()
    if "self-signed" in text or "self signed" in text:
        return "self-signed certificate"
    if "certificate verify failed" in text and ("unable to get local issuer" in text or "unable to verify" in text or "unknown ca" in text):
        return "untrusted certificate chain"
    return None


def enable_auto_insecure_https(url: str, reason: str) -> bool:
    if not cfg.auto_insecure_https or cfg.insecure_https:
        return False
    p = urlparse(url)
    if p.scheme != "https" or not is_target_onion_url(url):
        return False
    cfg.auto_insecure_https_reason = reason
    urllib3.disable_warnings(InsecureRequestWarning)
    return True


class DownloadLimitExceeded(RequestException):
    pass


class RequestBudgetExceeded(RequestException):
    pass


def _same_target_port(url: str) -> bool:
    p = urlparse(url)
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return False
    if cfg.target_port is None:
        return port in (80, 443) and port == (443 if p.scheme == "https" else 80)
    return port == cfg.target_port


def _permitted_request(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in {"http", "https"} or p.username or p.password or not p.hostname:
        return False
    if is_target_onion_url(url):
        return _same_target_port(url)
    if cfg.clearnet_url:
        mirror = urlparse(cfg.clearnet_url)
        if (p.scheme, p.hostname, p.port) == (mirror.scheme, mirror.hostname, mirror.port):
            return True
    return p.scheme == "https" and p.hostname == "check.torproject.org" and p.port in (None, 443)


def _request_once(method: str, url: str, timeout: float, verify: bool, headers: dict[str, str]):
    global _last_request_at
    with _request_lock:
        if cfg.started_at and time.monotonic() - cfg.started_at > cfg.max_duration:
            raise RequestBudgetExceeded("Scan time budget exceeded")
        if cfg.requests_made >= cfg.max_requests:
            raise RequestBudgetExceeded("Scan request budget exceeded")
        since = time.monotonic() - _last_request_at
        if cfg.started_at and cfg.sleep > since:
            time.sleep(cfg.sleep - since)
        cfg.requests_made += 1
        _last_request_at = time.monotonic()
    with session.request(method, url, timeout=timeout, allow_redirects=False, verify=verify, headers=headers or None, stream=True, proxies=dict(session.proxies)) as response:
        content = bytearray()
        if method.upper() != "HEAD":
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                if len(content) + len(chunk) > cfg.max_body_bytes:
                    raise DownloadLimitExceeded(f"Response exceeds {cfg.max_body_bytes} decompressed bytes")
                content.extend(chunk)
                if cfg.started_at and time.monotonic() - cfg.started_at > cfg.max_duration:
                    raise RequestBudgetExceeded("Scan time budget exceeded")
        response._content = bytes(content)
        response._content_consumed = True
        return response


def request(
    method: str,
    url: str,
    *,
    timeout: Optional[float] = None,
    allow_redirects: bool = False,
    verify: Optional[bool] = None,
    headers: Optional[dict[str, str]] = None,
    send_cookie: bool = True,
):
    if not _permitted_request(url):
        raise ValueError("Request outside approved target origin blocked")
    if allow_redirects:
        raise ValueError("Automatic redirects are disabled; use fetch_with_policy")
    session.trust_env = False
    if cfg.tor_mode == "socks":
        if not session.proxies.get("http", "").startswith("socks5h://") or not session.proxies.get("https", "").startswith("socks5h://"):
            raise RuntimeError("Tor SOCKS5h proxy is not configured")
    elif cfg.tor_mode == "transparent":
        if session.proxies:
            raise RuntimeError("Proxy configuration must be empty in transparent Tor mode")
    else:
        raise RuntimeError("Invalid Tor transport mode")
    if timeout is None:
        timeout = cfg.http_timeout
    if verify is None:
        verify = not ((cfg.insecure_https or cfg.auto_insecure_https_reason) and is_target_onion_url(url))
    if verify is False and is_target_onion_url(url) and not (cfg.insecure_https or cfg.auto_insecure_https_reason):
        raise ValueError("Unverified TLS requires explicit target-scoped permission")
    if not is_target_onion_url(url):
        verify = True
    req_headers = dict(headers or {})
    if send_cookie and cfg.cookie_header and is_target_onion_url(url):
        req_headers["Cookie"] = cfg.cookie_header
    cache = cfg.response_cache if method.upper() in {"GET", "HEAD"} and cfg.started_at else None
    def cacheable(result) -> bool:
        return (result.status_code not in {429, 500, 502, 503, 504}
                and len(result.content or b"") <= 131072
                and "Set-Cookie" not in result.headers
                and cache is not None and len(cache) < 32)
    cache_key = (method.upper(), url, bool(verify), tuple(sorted(req_headers.items())))
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    last_error = None
    for attempt in range(max(1, cfg.retries + 1)):
        try:
            result = _request_once(method, url, timeout, verify, req_headers)
            if cacheable(result):
                cache[cache_key] = result
            return result
        except SSLError as e:
            reason = _tls_auto_insecure_reason(e)
            if verify and reason and enable_auto_insecure_https(url, reason):
                verify = False
                result = _request_once(method, url, timeout, verify, req_headers)
                if cacheable(result):
                    cache[(method.upper(), url, False, tuple(sorted(req_headers.items())))] = result
                return result
            raise
        except (DownloadLimitExceeded, RequestBudgetExceeded):
            raise
        except RequestException as e:
            last_error = e
            if attempt >= cfg.retries or not should_retry_error(classify_network_error(e)["kind"]):
                raise
            time.sleep(min(0.35 * (attempt + 1), 1.5))
    raise last_error or RuntimeError("Request failed")


def same_onion_host(base_url: str, full_url: str) -> bool:
    b = (urlparse(base_url).hostname or "").lower()
    h = (urlparse(full_url).hostname or "").lower()
    return bool(b and h and b == h)


def _policy_violation(url: str) -> Optional[dict[str, Any]]:
    p = urlparse(url)
    host = (p.hostname or "").lower()

    if p.scheme not in {"http", "https"} or not host.endswith(".onion"):
        return {
            "response": None,
            "leak": url,
            "redirect_chain": [],
            "final_url": url,
            "error": "non-onion URL blocked by policy",
            "error_kind": "clearnet_blocked",
        }

    if cfg.target_host and host != cfg.target_host:
        return {
            "response": None,
            "leak": url,
            "redirect_chain": [],
            "final_url": url,
            "error": "cross-onion URL blocked by policy",
            "error_kind": "cross_onion_blocked",
        }

    if not _same_target_port(url):
        return {"response": None, "leak": url, "redirect_chain": [], "final_url": url, "error": "port outside approved target scope", "error_kind": "port_blocked"}

    return None


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
        policy_error = _policy_violation(current)
        if policy_error:
            policy_error["redirect_chain"] = visited
            return policy_error

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

        current = urljoin(current, loc)

    return {"response": None, "leak": None, "redirect_chain": visited, "final_url": current, "error": "too many redirects", "error_kind": "redirect_loop"}



def _looks_like_html(raw: bytes, ct: str) -> bool:
    c = (ct or "").lower()
    if "text/html" in c or "application/xhtml+xml" in c:
        return True
    s = (raw or b"")[:512].lstrip()
    if not s:
        return False
    if s.lower().startswith((b"<!doctype", b"<html", b"<head", b"<body")):
        return True
    return b"<html" in s.lower()

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

def _fallback_path(url: str) -> str:
    parsed = urlparse(url or "")
    path = re.sub(r"/+", "/", parsed.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def _fallback_destination(url: str, request_url: str = "") -> str:
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    authority = f"{host}:{port}" if port else host
    path = _fallback_path(url)
    request_path = _fallback_path(request_url) if request_url else ""
    if request_path and request_path != "/" and path != request_path:
        if request_path in path:
            path = path.replace(request_path, "/__requested_path__", 1)
        else:
            request_name = request_path.rsplit("/", 1)[-1]
            if len(request_name) >= 6 and request_name in path:
                path = path.replace(request_name, "__requested_path__", 1)
    return f"{authority}{path}"


def _soft404_normalize(text: str, response_url: str = "", request_url: str = "") -> str:
    value = (text or "").lower()[:65536]
    replacements = set()
    for raw_url in (response_url or "", request_url or ""):
        parsed = urlparse(raw_url)
        replacements.update({raw_url, parsed.path or "", (parsed.path or "").lstrip("/")})
    for item in sorted((x for x in replacements if len(x) >= 3), key=len, reverse=True):
        value = value.replace(item.lower(), " __requested_path__ ")
    value = re.sub(r"https?://[^\s\"'<>]+", " __url__ ", value)
    value = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", " __token__ ", value)
    value = re.sub(r"\b[0-9a-f]{24,}\b", " __token__ ", value)
    value = re.sub(r"\b\d{7,}\b", " __number__ ", value)
    value = re.sub(r"(?i)(csrf(?:token)?|nonce|request[-_]?id|token)(\s*[=:]\s*[\"']?)[^\"'\s<>]{6,}", r"\1\2__token__", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _soft404_signature(r, result: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    result = result or {}
    chain = list(result.get("redirect_chain") or [])
    final_url = result.get("final_url") or getattr(r, "url", "") or ""
    request_url = chain[0] if chain else (getattr(r, "url", "") or final_url)
    ct = (r.headers.get("Content-Type", "") or "").lower()
    normalized = _soft404_normalize(r.text or "", final_url, request_url)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", normalized, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    return {
        "status": r.status_code,
        "content_type": ct.split(";", 1)[0].strip(),
        "len": len(r.content or b""),
        "normalized": normalized,
        "title": title,
        "hash": hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest() if normalized else "",
        "redirected": bool(chain),
        "redirect_count": len(chain),
        "request_path": _fallback_path(request_url),
        "final_path": _fallback_path(final_url),
        "final_destination": _fallback_destination(final_url, request_url),
    }


def _soft404_signature_from_value(value) -> Optional[dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, dict) and "response" in value:
        r = value.get("response")
        if r is None:
            return None
        return _soft404_signature(r, value)
    return _soft404_signature(value)


def text_similarity(a: str, b: str) -> float:
    sa = set(re.findall(r"\w+", (a or "").lower()))
    sb = set(re.findall(r"\w+", (b or "").lower()))
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / max(len(sa | sb), 1)


def _soft404_signature_similarity(a: dict[str, Any], b: dict[str, Any], allow_redirect_destination: bool = True) -> float:
    if not a or not b:
        return 0.0
    if a.get("status") != b.get("status"):
        return 0.0
    act = a.get("content_type") or ""
    bct = b.get("content_type") or ""
    if act and bct and act != bct:
        return 0.0
    if allow_redirect_destination and (a.get("redirected") or b.get("redirected")):
        ad = a.get("final_destination") or ""
        bd = b.get("final_destination") or ""
        if ad and ad == bd:
            return 1.0
    an = a.get("normalized") or ""
    bn = b.get("normalized") or ""
    if not an or not bn:
        return 0.0
    if a.get("hash") and a.get("hash") == b.get("hash"):
        return 1.0
    sequence = SequenceMatcher(None, an, bn, autojunk=False).ratio()
    tokens = text_similarity(an, bn)
    alen = a.get("len", 0) or 0
    blen = b.get("len", 0) or 0
    length_score = 0.0
    if alen and blen:
        length_score = 1.0 - min(abs(alen - blen) / max(alen, blen), 1.0)
    return max(sequence, (tokens * 0.75) + (length_score * 0.25))


def get_soft404_baseline(base_url: str):
    base = base_url.rstrip("/")
    cache = cfg.soft404_cache
    if cache is not None and base in cache:
        return cache[base]
    tokens = [uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex]
    probe_paths = [
        f"/onionscout-missing-{tokens[0]}",
        f"/onionscout-missing-{tokens[1]}.zip",
        f"/onionscout-missing-{tokens[2]}/probe",
    ]
    samples = []
    for path in probe_paths:
        try:
            res = fetch_with_policy(base + path)
            r = res.get("response")
            if r is None or res.get("leak"):
                continue
            samples.append(_soft404_signature(r, res))
        except Exception:
            continue

    redirect_counts: dict[str, int] = {}
    for sample in samples:
        if sample.get("redirected") and sample.get("final_destination"):
            key = sample["final_destination"]
            redirect_counts[key] = redirect_counts.get(key, 0) + 1
    redirect_destinations = sorted(key for key, count in redirect_counts.items() if count >= 2)

    if redirect_destinations:
        stable_samples = [sample for sample in samples if sample.get("final_destination") in redirect_destinations]
        mode = "redirect"
    else:
        stable_samples = []
        for idx, sample in enumerate(samples):
            if any(
                idx != other_idx and _soft404_signature_similarity(sample, other, allow_redirect_destination=False) >= 0.82
                for other_idx, other in enumerate(samples)
            ):
                stable_samples.append(sample)
        mode = "content"

    baseline = {
        "stable": len(stable_samples) >= 2,
        "mode": mode,
        "samples": stable_samples,
        "redirect_destinations": redirect_destinations,
        "probes": len(probe_paths),
    } if samples else None
    if cache is not None:
        cache[base] = baseline
    return baseline


def looks_like_soft404(value, baseline) -> bool:
    if not baseline or value is None or not baseline.get("stable"):
        return False
    candidate = _soft404_signature_from_value(value)
    if not candidate:
        return False

    if baseline.get("mode") == "redirect":
        destinations = set(baseline.get("redirect_destinations") or [])
        destination = candidate.get("final_destination") or ""
        if destination and destination in destinations:
            for sample in baseline.get("samples") or []:
                if sample.get("final_destination") != destination:
                    continue
                if candidate.get("status") != sample.get("status"):
                    continue
                candidate_ct = candidate.get("content_type") or ""
                sample_ct = sample.get("content_type") or ""
                if candidate_ct and sample_ct and candidate_ct != sample_ct:
                    continue
                return True
        if candidate.get("redirected"):
            return False

    body = candidate.get("normalized") or ""
    generic_marker = bool(re.search(r"(?:\b404\b|not[ -]?found|page does not exist|page unavailable)", body, re.IGNORECASE))
    for sample in baseline.get("samples") or []:
        score = _soft404_signature_similarity(candidate, sample, allow_redirect_destination=False)
        clen = candidate.get("len", 0) or 0
        slen = sample.get("len", 0) or 0
        length_delta = abs(clen - slen) / max(clen, slen, 1)
        same_title = bool(candidate.get("title") and candidate.get("title") == sample.get("title"))
        if score >= 0.90:
            return True
        if score >= 0.82 and length_delta <= 0.25:
            return True
        if same_title and score >= 0.72 and length_delta <= 0.35:
            return True
        if generic_marker and score >= 0.68 and candidate.get("status") == sample.get("status"):
            return True
    return False

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

def _is_onion(full: str) -> bool:
    host = (urlparse(full).hostname or "").lower()
    return bool(host) and host.endswith(".onion")

def _resolve_literal_url(base_url: str, value: str) -> Optional[str]:
    v = (value or "").strip().strip('"\'')
    if not v or v.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return None
    if v.startswith("//"):
        scheme = urlparse(base_url).scheme or "http"
        v = f"{scheme}:{v}"
    return urljoin(base_url, v).split("#", 1)[0]

def _header_value(headers, name: str) -> str:
    if not headers:
        return ""
    return headers.get(name) or headers.get(name.lower()) or headers.get(name.title()) or ""

def _make_tor_socket(host: str, port: int, timeout: float):
    if cfg.tor_mode == "transparent":
        return socket.create_connection((host, port), timeout=timeout)
    if cfg.tor_mode != "socks":
        raise RuntimeError("Invalid Tor transport mode")
    if not socks:
        raise RuntimeError("PySocks not installed")
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, cfg.socks_host, cfg.socks_port, rdns=True)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def _make_socks_socket(host: str, port: int, timeout: float):
    return _make_tor_socket(host, port, timeout)

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
        if r is None or r.status_code != 200:
            return None
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if "html" not in ct:
            return None
        return _hash_html(r.text or "")
    except Exception:
        return None

def _looks_like_index_redirect_or_soft404(value, soft404_baseline, home_fp: Optional[str]) -> bool:
    if value is None:
        return True
    result = value if isinstance(value, dict) and "response" in value else None
    r = result.get("response") if result is not None else value
    if r is None:
        return True
    if looks_like_soft404(value, soft404_baseline):
        return True
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
        if r.status_code == 200 and "html" in ct and home_fp:
            if _hash_html(r.text or "") == home_fp:
                return True
    except Exception:
        pass
    return False

SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", re.IGNORECASE),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret": re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|bearer|authorization)\b\s*[:=]\s*[\"']?[^\"'\s<>]{8,}"),
    "jwt": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
}
