from __future__ import annotations

import re
from typing import Any, Optional

from ..findings import error_finding, finding
from .javascript import collect_javascript_sources

FINGERPRINT_PATTERNS = {
    "Canvas": [
        re.compile(r"\.getContext\(\s*['\"]2d['\"]", re.IGNORECASE),
        re.compile(r"\.toDataURL\s*\(", re.IGNORECASE),
        re.compile(r"\.getImageData\s*\(", re.IGNORECASE),
        re.compile(r"\.measureText\s*\(", re.IGNORECASE),
    ],
    "WebGL": [
        re.compile(r"\.getContext\(\s*['\"](?:webgl2?|experimental-webgl)['\"]", re.IGNORECASE),
        re.compile(r"WEBGL_debug_renderer_info", re.IGNORECASE),
        re.compile(r"UNMASKED_(?:VENDOR|RENDERER)_WEBGL", re.IGNORECASE),
    ],
    "WebRTC": [
        re.compile(r"(?:RTCPeerConnection|webkitRTCPeerConnection|mozRTCPeerConnection)", re.IGNORECASE),
        re.compile(r"\.createDataChannel\s*\(", re.IGNORECASE),
        re.compile(r"onicecandidate", re.IGNORECASE),
    ],
    "STUN/TURN": [
        re.compile(r"\b(?:stun|turns?):[^\s'\"<>]+", re.IGNORECASE),
        re.compile(r"iceServers", re.IGNORECASE),
    ],
    "AudioContext": [
        re.compile(r"(?:AudioContext|webkitAudioContext|OfflineAudioContext)", re.IGNORECASE),
        re.compile(r"\.createOscillator\s*\(", re.IGNORECASE),
        re.compile(r"\.createDynamicsCompressor\s*\(", re.IGNORECASE),
        re.compile(r"\.getFloatFrequencyData\s*\(", re.IGNORECASE),
    ],
    "Navigator/device": [
        re.compile(r"navigator\.(?:hardwareConcurrency|deviceMemory|plugins|mimeTypes|webdriver)", re.IGNORECASE),
        re.compile(r"(?:navigator\.)?mediaDevices\.enumerateDevices\s*\(", re.IGNORECASE),
    ],
}


def check_browser_fingerprinting(url: str, bundle: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    name = "Browser fingerprinting APIs"
    try:
        data = bundle or collect_javascript_sources(url)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak → {data['leak']}", raw=data, finding_type="deanon")
        if data.get("error") and not data.get("sources"):
            return finding(name, "warn", "low", data["error"], raw=data)

        hits = {}
        raw_hits = []
        for source in data.get("sources") or []:
            text = source.get("text") or ""
            source_name = source.get("source") or "unknown"
            for category, patterns in FINGERPRINT_PATTERNS.items():
                matched = []
                for rx in patterns:
                    m = rx.search(text)
                    if m:
                        matched.append(m.group(0)[:120])
                if matched:
                    hits.setdefault(category, []).append(source_name)
                    raw_hits.append({"category": category, "source": source_name, "matches": sorted(set(matched))})

        if not hits:
            return finding(name, "info", "info", "No common browser fingerprinting API indicators detected")

        normalized = {k: sorted(set(v))[:20] for k, v in sorted(hits.items())}
        risk = "medium" if any(k in normalized for k in {"WebRTC", "STUN/TURN"}) else "low"
        return finding(name, "warn", risk, normalized, raw=raw_hits[:80], finding_type="deanon")
    except Exception as e:
        return error_finding(name, e)
