from __future__ import annotations

import re
from typing import Any, Optional

from ..findings import error_finding, finding
from .javascript import collect_javascript_sources

ANALYTICS_PATTERNS = {
    "Google Analytics 4": re.compile(r"\bG-[A-Z0-9]{6,}\b", re.IGNORECASE),
    "Google Universal Analytics": re.compile(r"\bUA-\d{4,}-\d+\b", re.IGNORECASE),
    "Google Tag Manager": re.compile(r"\bGTM-[A-Z0-9]{4,}\b", re.IGNORECASE),
    "Google Ads": re.compile(r"\bAW-\d{5,}\b", re.IGNORECASE),
    "Meta Pixel": re.compile(r"\bfbq\s*\(\s*['\"]init['\"]\s*,\s*['\"]?(\d{5,})", re.IGNORECASE),
    "Matomo site ID": re.compile(r"(?:setSiteId['\"]?\s*,\s*['\"]?(\d+)|[?&]idsite=(\d+))", re.IGNORECASE),
    "Microsoft Clarity": re.compile(r"\bclarity\s*\(\s*['\"](?:set|identify|consent)['\"]", re.IGNORECASE),
    "Yandex Metrica": re.compile(r"\bym\s*\(\s*(\d{4,})\s*,", re.IGNORECASE),
    "Plausible domain": re.compile(r"data-domain\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
}


def check_analytics_ids(url: str, bundle: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    name = "Analytics identifiers"
    try:
        data = bundle or collect_javascript_sources(url)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak → {data['leak']}", raw=data, finding_type="deanon")
        texts = []
        if data.get("home_text"):
            texts.append(("html", data["home_text"]))
        for source in data.get("sources") or []:
            texts.append((source.get("source") or "unknown", source.get("text") or ""))
        for ref in data.get("external_scripts") or []:
            texts.append(("script-reference", ref))

        hits = []
        for source_name, text in texts:
            for label, rx in ANALYTICS_PATTERNS.items():
                for m in rx.finditer(text):
                    value = next((g for g in m.groups() if g), None) if m.groups() else m.group(0)
                    hits.append({"type": label, "value": (value or m.group(0))[:120], "source": source_name})
                    if len(hits) >= 80:
                        break
                if len(hits) >= 80:
                    break
            if len(hits) >= 80:
                break

        unique = []
        seen = set()
        for item in hits:
            key = (item["type"], item["value"], item["source"])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        if not unique:
            return finding(name, "info", "info", "No common analytics identifiers detected")
        return finding(name, "warn", "medium", unique[:50], raw={"count": len(unique)}, finding_type="deanon")
    except Exception as e:
        return error_finding(name, e)
