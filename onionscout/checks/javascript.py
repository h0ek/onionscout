from __future__ import annotations

import re
from typing import Any, Optional
from html.parser import HTMLParser
from urllib.parse import urljoin

from ..core import (
    IPV4_RE,
    JS_SCAN_MAX_BYTES,
    JS_SCAN_MAX_FILES,
    PROTO_REL_RE,
    SECRET_PATTERNS,
    SOURCE_MAP_RE,
    URL_LITERAL_RE,
    WEBSOCKET_RE,
    _is_clearnet,
    _is_onion,
    _resolve_candidates,
    _resolve_literal_url,
    fetch_with_policy,
    html_extract,
    is_valid_ipv4,
    same_onion_host,
)
from ..findings import error_finding, finding, no_response_finding

def _collect_js_sources_from_html(base_url: str, html: str) -> tuple[list[str], list[str]]:
    parser = html_extract(html or "")
    script_urls = []
    document_base = urljoin(base_url, parser.base_href) if parser.base_href else base_url
    for src in parser.script_srcs:
        full = _resolve_literal_url(document_base, src)
        if full:
            script_urls.append(full)

    inline_scripts = []
    for m in re.finditer(r"<script(?:\s[^>]*)?>([\s\S]*?)</script>", html or "", re.IGNORECASE):
        body = m.group(1) or ""
        if body.strip():
            inline_scripts.append(body[:JS_SCAN_MAX_BYTES])

    return sorted(set(script_urls)), inline_scripts[:JS_SCAN_MAX_FILES]

def _analyze_js_text(base_url: str, source_name: str, text: str) -> dict[str, Any]:
    urls = []
    for m in URL_LITERAL_RE.finditer(text or ""):
        full = _resolve_literal_url(base_url, m.group("url"))
        if full:
            urls.append(full)

    clearnet_urls = sorted(set(u for u in urls if _is_clearnet(u)))
    onion_urls = sorted(set(u for u in urls if _is_onion(u) and not same_onion_host(base_url, u)))
    ips = sorted(set(ip for ip in IPV4_RE.findall(text or "") if is_valid_ipv4(ip)))

    secret_hits = []
    for pname, rx in SECRET_PATTERNS.items():
        if pname == "url":
            continue
        for hit in rx.findall(text or ""):
            val = hit if isinstance(hit, str) else " ".join(hit)
            val = str(val)
            secret_hits.append({"type": pname, "match": val[:120]})
            if len(secret_hits) >= 20:
                break
        if len(secret_hits) >= 20:
            break

    source_maps = []
    for m in SOURCE_MAP_RE.finditer(text or ""):
        sm = (m.group(1) or "").strip().strip('"\'')
        if sm:
            source_maps.append(sm)

    return {
        "source": source_name,
        "clearnet_urls": clearnet_urls[:80],
        "cross_onion_urls": onion_urls[:40],
        "ips": ips[:40],
        "secret_candidates": secret_hits[:20],
        "source_maps": sorted(set(source_maps))[:20],
    }

def collect_javascript_sources(url: str) -> dict[str, Any]:
    res = fetch_with_policy(url)
    if res.get("leak"):
        return {"response": None, "leak": res["leak"], "error": None, "home_text": "", "sources": [], "external_scripts": [], "scripts_seen": 0, "scripts_fetched": 0}
    r = res.get("response")
    if r is None:
        return {"response": None, "leak": None, "error": f"No response ({res.get('error_kind', 'unknown')}: {res.get('error', 'unknown error')})", "home_text": "", "sources": [], "external_scripts": [], "scripts_seen": 0, "scripts_fetched": 0}

    home_text = r.text or ""
    script_urls, inline_scripts = _collect_js_sources_from_html(res.get("final_url") or url, home_text)
    sources = []
    external_scripts = []

    for idx, body in enumerate(inline_scripts, start=1):
        sources.append({"source": f"inline-script-{idx}", "text": body})

    fetched_js = 0
    for script_url in script_urls[:JS_SCAN_MAX_FILES]:
        if _is_clearnet(script_url) or not same_onion_host(url, script_url):
            external_scripts.append(script_url)
            continue
        js_res = fetch_with_policy(script_url)
        if js_res.get("leak"):
            external_scripts.append(js_res["leak"])
            continue
        jr = js_res.get("response")
        if jr is None or jr.status_code != 200 or not (jr.content or b""):
            continue
        if len(jr.content or b"") > JS_SCAN_MAX_BYTES:
            text = (jr.content or b"")[:JS_SCAN_MAX_BYTES].decode("utf-8", errors="ignore")
        else:
            text = jr.text or ""
        sources.append({"source": script_url, "text": text})
        fetched_js += 1

    return {
        "response": r,
        "leak": None,
        "error": None,
        "home_text": home_text,
        "sources": sources,
        "external_scripts": sorted(set(external_scripts)),
        "scripts_seen": len(script_urls),
        "scripts_fetched": fetched_js,
    }


def check_js_leaks(url: str, bundle: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    name = "JavaScript leaks"
    try:
        data = bundle or collect_javascript_sources(url)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak → {data['leak']}", raw=data, finding_type="deanon")
        if data.get("error") and not data.get("sources"):
            return finding(name, "warn", "low", data["error"], raw=data)

        analyses = []
        for source in data.get("sources") or []:
            analyses.append(_analyze_js_text(url, source.get("source") or "unknown", source.get("text") or ""))

        for script_url in data.get("external_scripts") or []:
            if _is_clearnet(script_url):
                analyses.append({"source": script_url, "clearnet_urls": [script_url], "cross_onion_urls": [], "ips": [], "secret_candidates": [], "source_maps": []})
            else:
                analyses.append({"source": script_url, "clearnet_urls": [], "cross_onion_urls": [script_url], "ips": [], "secret_candidates": [], "source_maps": []})

        source_map_hits = []
        for analysis in analyses:
            source_name = analysis.get("source") or url
            for sm in analysis.get("source_maps", []):
                full = _resolve_literal_url(source_name if str(source_name).startswith(("http://", "https://")) else url, sm)
                if not full:
                    continue
                if _is_clearnet(full):
                    source_map_hits.append(f"clearnet source map reference: {full}")
                    continue
                if not same_onion_host(url, full):
                    source_map_hits.append(f"cross-onion source map reference: {full}")
                    continue
                sm_res = fetch_with_policy(full)
                sr = sm_res.get("response")
                if sr is not None and sr.status_code == 200 and sr.content:
                    source_map_hits.append(f"accessible source map: {full}")

        clearnet = sorted(set(u for a in analyses for u in a.get("clearnet_urls", [])))
        cross_onion = sorted(set(u for a in analyses for u in a.get("cross_onion_urls", [])))
        ips = sorted(set(ip for a in analyses for ip in a.get("ips", [])))
        secrets = [item for a in analyses for item in a.get("secret_candidates", [])]
        evidence = {
            "scripts_seen": data.get("scripts_seen", 0),
            "scripts_fetched": data.get("scripts_fetched", 0),
            "clearnet_urls": clearnet[:100],
            "cross_onion_urls": cross_onion[:60],
            "ips": ips[:60],
            "secret_candidates": secrets[:30],
            "source_map_findings": sorted(set(source_map_hits))[:50],
        }

        if secrets:
            return finding(name, "warn", "high", evidence, raw=analyses, finding_type="leak")
        if clearnet or cross_onion or ips or source_map_hits:
            return finding(name, "warn", "medium", evidence, raw=analyses, finding_type="leak")
        inline_count = sum(1 for x in data.get("sources") or [] if str(x.get("source", "")).startswith("inline-script-"))
        return finding(name, "info", "info", f"No obvious JS leaks detected ({data.get('scripts_seen', 0)} script srcs, {inline_count} inline blocks)", raw=evidence)
    except Exception as e:
        return error_finding(name, e)


class ResourceExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base_href = None
        self.resources = []
        self.links = []
        self.css = []
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        values = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag == "base" and values.get("href") and self.base_href is None:
            self.base_href = values["href"]
        if tag == "style":
            self.in_style = True
        if values.get("style"):
            self.css.append(values["style"])
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        if tag == "link" and values.get("href"):
            if any(word in values.get("rel", "").lower() for word in ("stylesheet", "icon", "preload", "prefetch", "preconnect", "dns-prefetch", "modulepreload")):
                self.resources.append(values["href"])
            else:
                self.links.append(values["href"])
        if tag in {"script", "img", "iframe", "frame", "object", "embed", "source", "video", "audio", "track", "input", "form", "button"}:
            for key in ("src", "data", "poster", "action", "formaction"):
                if values.get(key):
                    self.resources.append(values[key])
            if values.get("srcset"):
                self.resources.extend(part.strip().split()[0] for part in values["srcset"].split(",") if part.strip())

    def handle_endtag(self, tag):
        if tag.lower() == "style":
            self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            self.css.append(data)


def _css_urls(css):
    found = re.findall(r"url\(\s*['\"]?([^'\")]+)", css, re.IGNORECASE)
    found += re.findall(r"@import\s+['\"]([^'\"]+)", css, re.IGNORECASE)
    return found[:100]


def check_external_resources(url: str) -> dict[str, Any]:
    name = "External resources"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect reference → {res['leak']}", raw=res, finding_type="dependency")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
        parser = ResourceExtractor()
        parser.feed((r.text or "")[:2_000_000])
        document_url = res.get("final_url") or url
        document_base = urljoin(document_url, parser.base_href) if parser.base_href else document_url
        active = set()
        links = set()
        cross_onion = set()
        for value in parser.resources + [item for css in parser.css for item in _css_urls(css)]:
            full = _resolve_literal_url(document_base, value)
            if full and _is_clearnet(full):
                active.add(full)
            elif full and _is_onion(full) and not same_onion_host(url, full):
                cross_onion.add(full)
        for value in parser.links:
            full = _resolve_literal_url(document_base, value)
            if full and _is_clearnet(full):
                links.add(full)
        evidence = {"active_resources": sorted(active)[:100], "cross_onion_resources": sorted(cross_onion)[:60], "external_links": sorted(links)[:100], "document_base": document_base}
        if active or cross_onion:
            return finding(name, "warn", "high" if active else "medium", evidence, raw=evidence, finding_type="dependency")
        if links:
            return finding(name, "info", "low", evidence, raw=evidence, finding_type="external_links")
        return finding(name, "info", "info", "No external resources or links detected", raw=evidence)
    except Exception as e:
        return error_finding(name, e)

def check_protocol_relative_links(url: str) -> dict[str, Any]:
    name = "Protocol-relative links"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
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

def check_meta_redirects(url: str) -> dict[str, Any]:
    name = "Meta-refresh"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
        p = html_extract(r.text or "")
        out = [x for x in _resolve_candidates(url, p.meta_refresh_targets) if _is_clearnet(x)]
        if out:
            return finding(name, "warn", "high", out, raw={"count": len(out)}, finding_type="deanon")
        return finding(name, "info", "info", "No meta-refresh to clearnet URLs")
    except Exception as e:
        return error_finding(name, e)

def check_form_actions(url: str) -> dict[str, Any]:
    name = "Form actions"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
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
        if r is None:
            return no_response_finding(name, res)
        wss = re.findall(WEBSOCKET_RE, r.text or "")
        out = [ws for ws in sorted(set(wss)) if _is_clearnet(ws)]
        if out:
            return finding(name, "warn", "high", out, raw={"count": len(out)}, finding_type="deanon")
        return finding(name, "info", "info", "No clearnet WebSocket endpoints")
    except Exception as e:
        return error_finding(name, e)

def check_captcha_leak(url: str) -> dict[str, Any]:
    name = "CAPTCHA leak"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None or r.status_code != 200:
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
