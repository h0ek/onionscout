from __future__ import annotations

import json
import re
import uuid
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from ..core import ONION_V3_HOST_RE, _looks_like_html, fetch_with_policy, html_extract, request, validate_onion_v3
from ..findings import error_finding, finding

import base64
import mmh3

def check_target_onion_address(url: str) -> dict[str, Any]:
    name = "Target onion address"
    host = (urlparse(url).hostname or "").lower()
    if host.endswith(".onion") and validate_onion_v3(host[:-6].split(".")[-1]):
        return finding(name, "ok", "info", "Target uses a valid onion v3 checksum and version", raw={"host": host})
    return finding(
        name,
        "warn",
        "medium",
        "Target hostname does not look like a standard 56-character onion v3 address",
        raw={"host": host},
        finding_type="policy",
    )

def check_tor_proxy() -> dict[str, Any]:
    name = "SOCKS/Tor connectivity check"
    try:
        r = request("GET", "https://check.torproject.org/api/ip", timeout=5, allow_redirects=False, send_cookie=False)
        ok = r.status_code == 200 and bool(r.json().get("IsTor"))
        return finding(name, "ok" if ok else "warn", "low", "Tor exit connectivity confirmed (not an onion circuit guarantee)" if ok else "Tor exit check failed (may be expected for pure onion usage)")
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
        if r is None:
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

def _favicon_content_ok(raw: bytes, ct: str) -> bool:
    if not raw or len(raw) < 8:
        return False
    if (ct or "").lower().startswith("image/svg+xml") or raw.lstrip().lower().startswith((b"<svg", b"<?xml")):
        return b"<svg" in raw[:512].lower()
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
        if r is not None and r.status_code == 200 and r.content:
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
        if r is None:
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
            if rf is not None and rf.status_code == 200 and rf.content and _favicon_content_ok(rf.content, rf.headers.get("Content-Type", "") or ""):
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
        if r is not None:
            etag = r.headers.get("ETag") or r.headers.get("Etag")
        if not etag:
            data = fetch_with_policy(url)
            if data.get("leak"):
                return finding(name, "fail", "high", f"Redirect leak \u2192 {data['leak']}", raw=data, finding_type="deanon")
            r = data.get("response")
            if r is not None:
                etag = r.headers.get("ETag") or r.headers.get("Etag")
        if etag:
            etag_clean = etag.strip().strip('"').strip("'")
            return finding(name, "ok", "low", [f'ETag: "{etag_clean}"', f"Query: http.headers.etag:{json.dumps(etag_clean)}"], raw={"etag": etag_clean})
        return finding(name, "info", "info", "No ETag header")
    except Exception as e:
        return error_finding(name, e)
