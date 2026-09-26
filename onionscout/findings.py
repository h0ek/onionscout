from __future__ import annotations

import hashlib
import re
from typing import Any

import requests

def group_for_finding_type(finding_type: str) -> str:
    return {
        "deanon": "de-anonymization",
        "dependency": "external dependency",
        "external_links": "external link",
        "exposure": "exposure",
        "leak": "metadata leak",
        "network": "network",
        "policy": "web hygiene",
        "internal": "internal",
        "info": "general",
    }.get((finding_type or "info").lower(), "general")

def finding(name: str, status: str, risk: str, evidence: Any, raw: Any = None, finding_type: str = "info") -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "finding_type": finding_type,
        "group": group_for_finding_type(finding_type),
        "risk": risk,
        "evidence": evidence,
        "raw": raw,
    }

def error_finding(name: str, e: Exception) -> dict[str, Any]:
    return finding(name, "error", "info", f"{type(e).__name__}: {e}", raw={"exception": repr(e)}, finding_type="internal")

def no_response_finding(name: str, res: dict[str, Any]) -> dict[str, Any]:
    kind = res.get("error_kind", "unknown")
    err = res.get("error", "unknown error")
    return finding(name, "warn", "low", f"No response ({kind}: {err})", raw=res)

def redact_sensitive(value: str) -> str:
    value = re.sub(r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)([^\r\n]+)", lambda m: m.group(1) + re.sub(r"(^|;\s*)([^=;\s]+)=([^;]*)", lambda c: c.group(1) + c.group(2) + "=[REDACTED]", m.group(2)), value)
    value = re.sub(r"(?i)(\b(?:authorization|x-api-key|api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[\"']?)([^\s,;<>\"']{6,})", r"\1[REDACTED]", value)
    value = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED_JWT]", value)
    return value


def make_json_safe(value: Any) -> Any:
    if isinstance(value, requests.Response):
        return {
            "url": redact_sensitive(value.url or ""),
            "status_code": value.status_code,
            "headers": {k: ("[REDACTED]" if k.lower() in {"set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key"} else redact_sensitive(v)) for k, v in (value.headers or {}).items()},
            "content_length": len(value.content or b""),
        }
    if isinstance(value, bytes):
        return {"bytes_len": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower() in {"set-cookie", "cookie", "authorization", "proxy-authorization", "password", "secret", "token", "api_key", "api-key"} else make_json_safe(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(v) for v in value]
    if isinstance(value, str):
        return redact_sensitive(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)
