from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from ..core import (
    CORS_PROBE_ORIGIN,
    LEAK_HEADERS,
    SECURITY_HEADER_EXPECTATIONS,
    _header_value,
    _is_clearnet,
    cfg,
    fetch_with_policy,
    request,
)
from ..findings import error_finding, finding, no_response_finding

def check_security_headers(url: str) -> dict[str, Any]:
    name = "Security headers"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak → {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)

        headers = r.headers or {}
        present = {}
        missing = []
        issues = []

        for hdr, desc in SECURITY_HEADER_EXPECTATIONS.items():
            val = _header_value(headers, hdr)
            if val:
                present[hdr] = val
            else:
                if hdr == "X-Frame-Options" and "frame-ancestors" in (_header_value(headers, "Content-Security-Policy").lower()):
                    present[hdr] = "covered by CSP frame-ancestors"
                    continue
                missing.append(f"{hdr} missing ({desc})")

        xcto = _header_value(headers, "X-Content-Type-Options")
        if xcto and xcto.lower().strip() != "nosniff":
            issues.append(f"X-Content-Type-Options is '{xcto}', expected 'nosniff'")

        if urlparse(url).scheme == "https" and not _header_value(headers, "Strict-Transport-Security"):
            missing.append("Strict-Transport-Security missing on HTTPS origin")

        evidence = {"present": present, "missing": missing, "issues": issues}
        if issues:
            return finding(name, "warn", "medium", evidence, raw=evidence, finding_type="policy")
        if len(missing) >= 3:
            return finding(name, "warn", "low", evidence, raw=evidence, finding_type="policy")
        if missing:
            return finding(name, "info", "low", evidence, raw=evidence, finding_type="policy")
        return finding(name, "ok", "low", "Common security headers present", raw=evidence, finding_type="policy")
    except Exception as e:
        return error_finding(name, e)

def check_cors(url: str) -> dict[str, Any]:
    name = "CORS headers"
    try:
        r = request("GET", url, allow_redirects=False, headers={"Origin": CORS_PROBE_ORIGIN})
        ac = {k: v for k, v in (r.headers.items() if r is not None else []) if k.lower().startswith("access-control-")}
        if not ac:
            return finding(name, "info", "info", "No CORS headers")

        acao = ac.get("Access-Control-Allow-Origin") or ac.get("access-control-allow-origin") or ""
        acac = ac.get("Access-Control-Allow-Credentials") or ac.get("access-control-allow-credentials") or ""
        issues = []
        if acao == "*":
            issues.append("Access-Control-Allow-Origin is wildcard (*)")
        if acao.lower() == CORS_PROBE_ORIGIN:
            issues.append("Access-Control-Allow-Origin reflects arbitrary Origin")
        if acac.lower() == "true" and acao.lower() == CORS_PROBE_ORIGIN:
            issues.append("Credentialed CORS reflects arbitrary Origin")
        elif acac.lower() == "true" and acao == "*":
            issues.append("Wildcard with credentials is rejected by browsers")
        if acao and _is_clearnet(acao):
            issues.append(f"Clearnet origin allowed: {acao}")

        evidence = {"headers": ac, "issues": issues}
        if any("Credentialed" in x or "reflects" in x for x in issues):
            return finding(name, "warn", "high", evidence, raw=evidence, finding_type="policy")
        if issues:
            return finding(name, "warn", "medium", evidence, raw=evidence, finding_type="policy")
        return finding(name, "info", "low", evidence, raw=evidence)
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
        found = [f"{k}: {r.headers[k]}" for k in keys if r is not None and k in r.headers]
        if found:
            return finding(name, "warn", "high", found)
        if r is None:
            return no_response_finding(name, res)
        return finding(name, "info", "info", "No proxy-related headers")
    except Exception as e:
        return error_finding(name, e)

def check_onion_location(url: str) -> dict[str, Any]:
    name = "Onion-Location header"
    try:
        target_host = (urlparse(url).hostname or "").lower()

        if cfg.clearnet_url:
            r = request("GET", cfg.clearnet_url, allow_redirects=False, verify=True, send_cookie=False)
            val = r.headers.get("Onion-Location") or r.headers.get("onion-location")
            if not val:
                return finding(name, "info", "info", f"No Onion-Location header on clearnet URL ({cfg.clearnet_url})", raw={"clearnet_url": cfg.clearnet_url, "status_code": r.status_code})
            resolved = urljoin(cfg.clearnet_url, val)
            onion_host = (urlparse(resolved).hostname or "").lower()
            evidence = {"clearnet_url": cfg.clearnet_url, "header": val, "resolved": resolved, "target_host": target_host}
            if onion_host == target_host:
                return finding(name, "ok", "low", f"Clearnet Onion-Location points to target onion: {resolved}", raw=evidence)
            if onion_host.endswith(".onion"):
                return finding(name, "warn", "medium", f"Clearnet Onion-Location points to a different onion: {resolved}", raw=evidence, finding_type="policy")
            return finding(name, "warn", "medium", f"Clearnet Onion-Location is not a valid onion URL: {resolved}", raw=evidence, finding_type="policy")

        r = request("GET", url, allow_redirects=False)
        val = r.headers.get("Onion-Location") or r.headers.get("onion-location")
        if val:
            return finding(name, "info", "low", f"Onion-Location on onion origin: {val}", raw={"value": val, "note": "This header is mainly useful on a clearnet HTTPS mirror."})
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
        found = [f"{k}: {r.headers.get(k)}" for k in LEAK_HEADERS if r is not None and k in r.headers]
        if found:
            return finding(name, "warn", "medium", found)
        if r is None:
            return no_response_finding(name, res)
        return finding(name, "info", "info", "No obvious header leaks")
    except Exception as e:
        return error_finding(name, e)

def check_http_availability(url: str) -> dict[str, Any]:
    name = "HTTP origin availability"
    res = fetch_with_policy(url, timeout=min(cfg.http_timeout, 10.0), max_hops=2)
    r = res.get("response")
    if r is not None:
        return finding(name, "ok", "info", [
            f"Selected origin: {url}",
            f"HTTP status: {r.status_code}",
            f"Final URL: {res.get('final_url', url)}",
        ], raw=res, finding_type="network")
    return finding(name, "warn", "low", f"No HTTP response ({res.get('error_kind', 'unknown')}: {res.get('error', 'unknown error')})", raw=res, finding_type="network")

def check_csp_related(url: str) -> dict[str, Any]:
    name = "CSP / Report-To / NEL / Link"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")

        r = res.get("response")
        if r is None:
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
            for directive in val.split(";"):
                words = directive.strip().split()
                if not words or words[0].lower() not in {"default-src", "script-src", "style-src", "img-src", "font-src", "connect-src", "frame-src", "media-src", "object-src", "form-action", "report-uri"}:
                    continue
                for token in words[1:]:
                    token = token.strip('"\'')
                    if token.lower() in {"http:", "https:"}:
                        clear.append(token.lower())
                        continue
                    if token.startswith(("*.", "//")) or ("." in token and not token.startswith(("'", "data:", "blob:"))):
                        candidate = token if token.startswith(("http://", "https://")) else "https://" + token.lstrip("/")
                        if _is_clearnet(candidate):
                            clear.append(candidate)
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

def analyze_set_cookie(url: str) -> dict[str, Any]:
    name = "Set-Cookie analysis"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect reference → {res['leak']}", raw=res, finding_type="dependency")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
        raw_headers = []
        if getattr(r, "raw", None) is not None and getattr(r.raw, "headers", None) is not None:
            raw_headers = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
        cookies = raw_headers or ([r.headers["Set-Cookie"]] if "Set-Cookie" in r.headers else [])
        if not cookies:
            return finding(name, "info", "info", "No Set-Cookie header")
        findings = []
        for item in cookies:
            segments = [x.strip() for x in item.split(";")]
            cookie_name = segments[0].split("=", 1)[0].strip()
            attributes = {x.split("=", 1)[0].strip().lower(): x.split("=", 1)[1].strip() if "=" in x else "" for x in segments[1:]}
            issues = []
            if "secure" not in attributes:
                issues.append("missing Secure (review Tor Browser HTTPS semantics)")
            if "httponly" not in attributes:
                issues.append("missing HttpOnly (only needed if JavaScript access is not required)")
            if "samesite" not in attributes:
                issues.append("missing SameSite")
            if attributes.get("samesite", "").lower() == "none" and "secure" not in attributes:
                issues.append("SameSite=None requires Secure")
            if cookie_name.startswith("__Host-") and ("secure" not in attributes or "domain" in attributes or attributes.get("path") != "/"):
                issues.append("invalid __Host- attributes")
            if cookie_name.startswith("__Secure-") and "secure" not in attributes:
                issues.append("invalid __Secure- attributes")
            findings.append(f"{cookie_name}=[REDACTED] -> " + (", ".join(issues) if issues else "OK"))
        risk = "medium" if any("missing Secure" in x or "invalid __" in x for x in findings) else "low"
        status = "warn" if any("-> OK" not in x for x in findings) else "ok"
        return finding(name, status, risk, findings, raw={"count": len(cookies)})
    except Exception as e:
        return error_finding(name, e)
