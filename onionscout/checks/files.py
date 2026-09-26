from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

from ..core import (
    BACKUP_ARCHIVE_PATHS_EXTENDED,
    DOCUMENT_METADATA_MAX_BYTES,
    BACKUP_ARCHIVE_PATHS_SAFE,
    DIRECTORY_LISTING_PATHS,
    DIRECTORY_LISTING_RE,
    DANGEROUS_HTTP_METHODS,
    ERROR_PAGE_PATTERNS,
    HTTP_METHODS_TO_CHECK,
    IPV4_RE,
    LINUX_PATH_RE,
    NGINX_STUB_RE,
    SECURITYTXT_DIRECTIVE_RE,
    SECURITYTXT_MAX_BYTES,
    SENSITIVE_PATHS,
    URL_LITERAL_RE,
    WINDOWS_PATH_RE,
    WELL_KNOWN_PATHS,
    _get_home_fingerprint,
    _hash_html,
    _is_clearnet,
    _looks_like_html,
    _resolve_literal_url,
    cfg,
    fetch_with_policy,
    find_valid_ipv4,
    get_soft404_baseline,
    is_valid_ipv4,
    looks_like_soft404,
)
from ..findings import error_finding, finding, no_response_finding

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
            if r is None:
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
            if r is None:
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

def check_files_and_paths(url: str) -> dict[str, Any]:
    name = "Files & paths"
    try:
        found = []
        raw = []
        baseline = get_soft404_baseline(url.rstrip("/"))
        for path in SENSITIVE_PATHS:
            target = f"{url.rstrip('/')}{path}"
            res = fetch_with_policy(target)
            if res.get("leak"):
                found.append(f"{path} redirect leak → {res['leak']}")
                raw.append({"path": path, "leak": res.get("leak")})
                continue
            r = res.get("response")
            if r is None:
                continue
            if r.status_code == 200 and not looks_like_soft404(res, baseline):
                ct = (r.headers.get("Content-Type", "") or "").lower()
                size = len(r.content or b"")
                sample = (r.text or "")[:120].replace("\n", " ").strip() if "text" in ct or "json" in ct or "html" in ct or not ct else ""
                found.append(f"{path} found (HTTP 200, {size} bytes, ct={ct or 'n/a'})")
                raw.append({"path": path, "status": r.status_code, "content_type": ct, "size": size, "sample": sample})
            elif r.status_code in (401, 403) and path in {"/.git/config", "/.env", "/server-status", "/server-info", "/admin"}:
                found.append(f"{path} protected (HTTP {r.status_code})")
                raw.append({"path": path, "status": r.status_code})
        if not found:
            return finding(name, "info", "info", "No sensitive files or paths found")
        high_markers = ("/.env", "/.git/config", "backup", "dump.sql", "db.sql", "phpinfo")
        risk = "high" if any(any(m in x.lower() for m in high_markers) and "HTTP 200" in x for x in found) else "medium"
        status = "warn" if any("HTTP 200" in x or "redirect leak" in x for x in found) else "info"
        return finding(name, status, risk, found, raw={"count": len(found), "items": raw}, finding_type="exposure")
    except Exception as e:
        return error_finding(name, e)

def check_http_methods(url: str) -> dict[str, Any]:
    name = "HTTP methods"
    try:
        base = url.rstrip("/") + "/"
        found = []
        raw = []

        opt = fetch_with_policy(base, method="OPTIONS")
        if opt.get("leak"):
            return finding(name, "fail", "high", f"OPTIONS redirect leak → {opt['leak']}", raw=opt, finding_type="deanon")

        allow_methods = set()
        r_opt = opt.get("response")
        if r_opt is not None:
            allow = r_opt.headers.get("Allow", "") or r_opt.headers.get("Access-Control-Allow-Methods", "")
            for m in re.split(r"[,\s]+", allow.upper()):
                if m:
                    allow_methods.add(m.strip())
            raw.append({"method": "OPTIONS", "status": r_opt.status_code, "allow": allow})

        advertised_dangerous = sorted(allow_methods & DANGEROUS_HTTP_METHODS)
        for method in advertised_dangerous:
            found.append(f"{method}: advertised in Allow header (not verified as executable)")

        trace = fetch_with_policy(base, method="TRACE", max_hops=0)
        if trace.get("leak"):
            found.append(f"TRACE: redirect leak → {trace['leak']}")
            raw.append({"method": "TRACE", "leak": trace.get("leak")})
        else:
            r_trace = trace.get("response")
            if r_trace is not None:
                raw.append({"method": "TRACE", "status": r_trace.status_code, "allow": r_trace.headers.get("Allow", "")})
                if r_trace.status_code not in (400, 401, 403, 404, 405, 501):
                    found.append(f"TRACE: HTTP {r_trace.status_code} (reflection not verified)")

        if found:
            risk = "medium"
            return finding(name, "warn", risk, found, raw=raw, finding_type="exposure")
        if allow_methods:
            return finding(name, "info", "low", f"Allowed methods: {', '.join(sorted(allow_methods))}", raw=raw)
        return finding(name, "info", "info", "No risky HTTP methods detected", raw=raw)
    except Exception as e:
        return error_finding(name, e)

def check_directory_listing(url: str) -> dict[str, Any]:
    name = "Directory listing"
    try:
        base = url.rstrip("/")
        hits = []
        raw = []
        baseline = get_soft404_baseline(base)

        for path in DIRECTORY_LISTING_PATHS:
            target = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
            res = fetch_with_policy(target)
            if res.get("leak"):
                hits.append(f"{path} redirect leak → {res['leak']}")
                raw.append({"path": path, "leak": res.get("leak")})
                continue
            r = res.get("response")
            if r is None or r.status_code != 200 or looks_like_soft404(res, baseline):
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            text = r.text or ""
            if ("html" in ct or "text/plain" in ct or not ct) and DIRECTORY_LISTING_RE.search(text):
                hits.append(f"{path} looks like directory listing")
                raw.append({"path": path, "status": r.status_code, "content_type": ct, "sample": text[:160]})

        if hits:
            return finding(name, "warn", "high", hits, raw=raw, finding_type="exposure")
        return finding(name, "info", "info", "No directory listing detected")
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

def _parse_securitytxt_directives(body_text: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_line in (body_text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        directives.setdefault(key, []).append(val)
    return directives

def _parse_securitytxt_expires(value: str) -> Optional[datetime]:
    raw = (value or "").strip()
    if not raw:
        return None
    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")
    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _securitytxt_analysis(body_text: str, path: str = "") -> dict[str, Any]:
    directives = _parse_securitytxt_directives(body_text)
    issues = []
    leaks = []

    if "contact" not in directives:
        issues.append("Contact directive missing")
    if "expires" not in directives:
        issues.append("Expires directive missing")

    expires_values = directives.get("expires", [])
    if expires_values:
        exp = _parse_securitytxt_expires(expires_values[0])
        if not exp:
            issues.append(f"Expires is not a valid date: {expires_values[0]}")
        elif exp <= datetime.now(timezone.utc):
            issues.append(f"Expires is in the past: {expires_values[0]}")

    for key in ("contact", "encryption", "acknowledgments", "policy", "canonical", "hiring"):
        for val in directives.get(key, []):
            for match in URL_LITERAL_RE.finditer(val):
                full = _resolve_literal_url("http://placeholder.onion", match.group("url"))
                if full and _is_clearnet(full):
                    leaks.append(f"{key}: {full}")

    canonical_values = directives.get("canonical", [])
    if canonical_values:
        for c in canonical_values:
            c = c.strip()
            if not c.startswith(("http://", "https://")):
                issues.append(f"Canonical is not an absolute URL: {c}")
            if "/.well-known/security.txt" not in c:
                issues.append(f"Canonical does not point to /.well-known/security.txt: {c}")
    elif path == "/.well-known/security.txt":
        issues.append("Canonical directive missing")

    if path == "/security.txt":
        issues.append("Root /security.txt is legacy compatibility; prefer /.well-known/security.txt")

    return {"directives": directives, "issues": sorted(set(issues)), "clearnet_urls": sorted(set(leaks))}

def _securitytxt_invalid_reason(r) -> Optional[str]:
    if r is None:
        return "no response"
    ct = (r.headers.get("Content-Type", "") or "").lower()
    raw = r.content or b""
    if len(raw) == 0:
        return "empty body"
    if len(raw) > SECURITYTXT_MAX_BYTES:
        return f"too large ({len(raw)} bytes)"
    if _looks_like_html(raw, ct):
        return f"looks like HTML (Content-Type={ct or 'n/a'})"
    if ct and not (ct.startswith("text/plain") or ct.startswith("text/security") or "charset=" in ct or "octet-stream" in ct):
        return f"suspicious Content-Type ({ct})"
    text = (r.text or "").strip()
    if not _looks_like_security_txt(text):
        directives = _parse_securitytxt_directives(text)
        if not directives:
            return "no security.txt directives found"
        if "contact" not in directives or "expires" not in directives:
            return "missing required directives (need at least Contact and Expires)"
    return None

def _fetch_security_txt(base_url: str, path: str) -> dict[str, Any]:
    name = f"security.txt ({'root' if path == '/security.txt' else '.well-known'})"
    try:
        base = base_url.rstrip("/")
        baseline = get_soft404_baseline(base)
        res = fetch_with_policy(f"{base}{path}")
        if res.get("leak"):
            return finding(name, "fail", "high", f"{path}: redirect leak → {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return finding(name, "warn", "low", f"{path}: no response")
        if r.status_code != 200:
            return finding(name, "info", "info", f"{path}: not found (HTTP {r.status_code})", raw={"status_code": r.status_code})
        if looks_like_soft404(res, baseline):
            return finding(name, "info", "info", f"{path}: not found (soft-404/catch-all response)", raw={"status_code": r.status_code, "soft404": True})
        reason = _securitytxt_invalid_reason(r)
        if reason:
            ct = r.headers.get("Content-Type", "") or "n/a"
            sample = (r.text or "")[:120].replace("\n", " ").strip()
            return finding(name, "warn", "medium", f"{path}: HTTP 200 but NOT valid security.txt ({reason}); Content-Type={ct}; sample='{sample}'")

        lines = [ln.strip() for ln in (r.text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
        analysis = _securitytxt_analysis(r.text or "", path)
        evidence = {"path": path, "lines": lines[:20], **analysis}

        if analysis["clearnet_urls"]:
            return finding(name, "warn", "medium", evidence, raw=evidence, finding_type="leak")
        if analysis["issues"]:
            return finding(name, "warn", "low", evidence, raw=evidence, finding_type="policy")
        return finding(name, "ok", "low", lines[:12], raw=evidence)
    except Exception as e:
        return error_finding(name, e)

def check_well_known(url: str) -> dict[str, Any]:
    name = "Well-known endpoints"
    try:
        base = url.rstrip("/")
        baseline = get_soft404_baseline(base)
        hits = []
        for pth in WELL_KNOWN_PATHS:
            res = fetch_with_policy(f"{url.rstrip('/')}{pth}")
            if res.get("leak"):
                hits.append(f"{pth} -> redirect leak \u2192 {res['leak']}")
                continue
            r = res.get("response")
            if r is not None and r.status_code == 200:
                if looks_like_soft404(res, baseline):
                    continue
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

def _backup_paths_for_profile() -> list[str]:
    if cfg.profile == "extended":
        return BACKUP_ARCHIVE_PATHS_EXTENDED
    return BACKUP_ARCHIVE_PATHS_SAFE

def check_backup_archives(url: str) -> dict[str, Any]:
    name = "Backup/archive leaks"
    try:
        base = url.rstrip("/")
        baseline = get_soft404_baseline(base)
        hits = []
        raw = []
        for path in _backup_paths_for_profile():
            target = f"{base}{path}"
            res = fetch_with_policy(target, method="HEAD")
            if res.get("leak"):
                hits.append(f"{path} redirect leak \u2192 {res['leak']}")
                raw.append({"path": path, "leak": res.get("leak")})
                continue
            r = res.get("response")
            if r is None or r.status_code in (404, 405):
                res = fetch_with_policy(target)
                if res.get("leak"):
                    hits.append(f"{path} redirect leak \u2192 {res['leak']}")
                    raw.append({"path": path, "leak": res.get("leak")})
                    continue
                r = res.get("response")
            if r is None:
                continue
            if r.status_code in (401, 403):
                raw.append({"path": path, "status": r.status_code, "protected": True})
                continue
            if r.status_code != 200:
                continue
            size = int(r.headers.get("Content-Length") or len(r.content or b"") or 0)
            if size and size > DOCUMENT_METADATA_MAX_BYTES * 50:
                hits.append(f"{path} large backup-like candidate (HTTP 200, {size} bytes, not downloaded)")
                raw.append({"path": path, "status": r.status_code, "size": size, "skipped": "too large"})
                continue
            if not (r.content or b""):
                res = fetch_with_policy(target)
                if res.get("leak"):
                    hits.append(f"{path} redirect leak \u2192 {res['leak']}")
                    raw.append({"path": path, "leak": res.get("leak")})
                    continue
                r = res.get("response")
                if r is None or r.status_code != 200:
                    continue
            if looks_like_soft404(res, baseline):
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            size = int(r.headers.get("Content-Length") or len(r.content or b"") or 0)
            if _looks_like_html(r.content or b"", ct) and not re.search(r"\.(?:sql|sqlite|bak|zip|tar|tgz|gz)(?:$|[?#])", path, re.IGNORECASE):
                continue
            hits.append(f"{path} found (HTTP 200, {size or 'unknown'} bytes, ct={ct or 'n/a'})")
            raw.append({"path": path, "status": r.status_code, "content_type": ct, "size": size})
        if hits:
            return finding(name, "warn", "high", hits[:80], raw={"count": len(hits), "items": raw}, finding_type="exposure")
        return finding(name, "info", "info", "No backup/archive files detected", raw={"checked": len(_backup_paths_for_profile())})
    except Exception as e:
        return error_finding(name, e)

def check_error_page_fingerprints(url: str) -> dict[str, Any]:
    name = "Error page fingerprints"
    try:
        base = url.rstrip("/")
        target = f"{base}/onionscout-{uuid.uuid4().hex}"
        home_fp = _get_home_fingerprint(base)
        res = fetch_with_policy(target)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Error page redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
        ct = (r.headers.get("Content-Type", "") or "").lower()
        text = r.text or ""
        if r.status_code == 200 and "html" in ct and home_fp and _hash_html(text) == home_fp:
            return finding(name, "info", "info", "Random path returned homepage-like content")
        hits = []
        for label, rx in ERROR_PAGE_PATTERNS:
            if rx.search(text):
                hits.append(label)
        trace_paths = sorted(set(WINDOWS_PATH_RE.findall(text) + LINUX_PATH_RE.findall(text)))[:20]
        ips = sorted(set(ip for ip in IPV4_RE.findall(text) if is_valid_ipv4(ip)))[:20]
        evidence = {"status_code": r.status_code, "fingerprints": hits, "paths": trace_paths, "ips": ips, "sample": text[:240].replace("\n", " ").strip()}
        if hits or trace_paths or ips:
            risk = "high" if trace_paths or ips or any("debug" in x.lower() or "trace" in x.lower() for x in hits) else "medium"
            return finding(name, "warn", risk, evidence, raw=evidence, finding_type="leak")
        return finding(name, "info", "info", f"No verbose error page fingerprint detected (HTTP {r.status_code})", raw=evidence)
    except Exception as e:
        return error_finding(name, e)
