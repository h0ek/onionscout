from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Optional

from ..core import _is_clearnet, _is_onion, _resolve_literal_url, same_onion_host
from ..findings import error_finding, finding
from .javascript import collect_javascript_sources

SUSPICIOUS_JS_PATTERNS = [
    ("eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("new Function", re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)),
    ("eval+atob", re.compile(r"eval\s*\(\s*(?:window\.)?atob\s*\(", re.IGNORECASE)),
    ("document.write+unescape", re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.IGNORECASE)),
    ("String.fromCharCode", re.compile(r"String\.fromCharCode\s*\(", re.IGNORECASE)),
    ("long encoded payload", re.compile(r"['\"][A-Za-z0-9+/]{240,}={0,2}['\"]")),
    ("dense hex escapes", re.compile(r"(?:\\x[0-9a-fA-F]{2}){12,}")),
]


class IframeExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.iframes = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "iframe":
            return
        data = {k.lower(): (v or "") for k, v in attrs}
        data["_hidden_attr"] = any(k.lower() == "hidden" for k, _ in attrs)
        self.iframes.append(data)


def _iframe_hidden(attrs: dict[str, Any]) -> bool:
    style = str(attrs.get("style") or "").replace(" ", "").lower()
    width = str(attrs.get("width") or "").strip().lower()
    height = str(attrs.get("height") or "").strip().lower()
    return bool(
        attrs.get("_hidden_attr")
        or "display:none" in style
        or "visibility:hidden" in style
        or "opacity:0" in style
        or re.search(r"(?:left|top):-\d{3,}(?:px)?", style)
        or (width in {"0", "0px"} and height in {"0", "0px"})
    )


def check_iframes_and_suspicious_js(url: str, bundle: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    name = "Iframes / suspicious JavaScript"
    try:
        data = bundle or collect_javascript_sources(url)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak → {data['leak']}", raw=data, finding_type="deanon")

        parser = IframeExtractor()
        parser.feed(data.get("home_text") or "")
        iframe_hits = []
        max_risk = "info"
        finding_type = "policy"

        for attrs in parser.iframes:
            src = str(attrs.get("src") or "").strip()
            full = _resolve_literal_url(url, src) if src else None
            hidden = _iframe_hidden(attrs)
            item = {"src": src or "inline/empty", "resolved": full, "hidden": hidden}
            if src.lower().startswith(("javascript:", "data:")):
                item["issue"] = "active inline iframe URI"
                max_risk = "high"
            elif full and _is_clearnet(full):
                item["issue"] = "clearnet iframe"
                max_risk = "high"
                finding_type = "deanon"
            elif full and _is_onion(full) and not same_onion_host(url, full):
                item["issue"] = "cross-onion iframe"
                if max_risk not in {"high"}:
                    max_risk = "medium"
                finding_type = "deanon"
            elif hidden:
                item["issue"] = "hidden iframe"
                if max_risk == "info":
                    max_risk = "low"
            else:
                continue
            iframe_hits.append(item)

        js_hits = []
        for source in data.get("sources") or []:
            text = source.get("text") or ""
            source_name = source.get("source") or "unknown"
            for label, rx in SUSPICIOUS_JS_PATTERNS:
                if rx.search(text):
                    js_hits.append({"indicator": label, "source": source_name})
                    if max_risk == "info":
                        max_risk = "low"

        unique_js = []
        seen = set()
        for item in js_hits:
            key = (item["indicator"], item["source"])
            if key not in seen:
                seen.add(key)
                unique_js.append(item)

        if not iframe_hits and not unique_js:
            return finding(name, "info", "info", "No hidden/external iframes or conservative suspicious-JavaScript indicators detected")

        evidence = {"iframes": iframe_hits[:40], "javascript_indicators": unique_js[:40]}
        return finding(name, "warn", max_risk, evidence, raw=evidence, finding_type=finding_type)
    except Exception as e:
        return error_finding(name, e)
