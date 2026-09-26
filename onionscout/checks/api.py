from __future__ import annotations

import json
import re
from typing import Any

from ..core import cfg, fetch_with_policy, get_soft404_baseline, looks_like_soft404
from ..findings import error_finding, finding

API_PATHS_SAFE = [
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/graphql/playground",
    "/debug",
    "/debug/pprof/",
    "/debug/vars",
]

API_PATHS_EXTENDED = API_PATHS_SAFE + [
    "/swagger/",
    "/docs",
    "/redoc",
    "/v2/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/__debug__",
    "/_debugbar/open",
    "/actuator",
    "/actuator/health",
]

SIGNATURES = [
    ("Swagger/OpenAPI", re.compile(r"(?:swagger-ui|\"swagger\"\s*:|\"openapi\"\s*:)", re.IGNORECASE)),
    ("GraphQL", re.compile(r"(?:GraphQL|Must provide query string|graphiql|graphql-playground)", re.IGNORECASE)),
    ("Go pprof", re.compile(r"(?:Types of profiles available|/debug/pprof/|goroutine profile)", re.IGNORECASE)),
    ("Go expvar", re.compile(r"\"cmdline\"\s*:|\"memstats\"\s*:", re.IGNORECASE)),
    ("Django debug", re.compile(r"(?:Django Version|Exception Type|DEBUG\s*=\s*True)", re.IGNORECASE)),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|console\.png", re.IGNORECASE)),
    ("Rails debug", re.compile(r"Action Controller: Exception caught|Rails\.root", re.IGNORECASE)),
    ("Laravel debug", re.compile(r"(?:Laravel|Whoops).*?(?:Stack trace|Exception)", re.IGNORECASE | re.DOTALL)),
]


def _classify_api_response(path: str, response) -> list[str]:
    text = response.text or ""
    hits = [label for label, rx in SIGNATURES if rx.search(text)]
    ct = (response.headers.get("Content-Type", "") or "").lower()
    if "json" in ct and response.status_code == 200:
        try:
            obj = response.json()
            if isinstance(obj, dict):
                if "openapi" in obj or "swagger" in obj:
                    hits.append("Swagger/OpenAPI")
                if path == "/debug/vars" and ("memstats" in obj or "cmdline" in obj):
                    hits.append("Go expvar")
        except (ValueError, json.JSONDecodeError):
            pass
    if path in {"/graphql", "/graphiql", "/graphql/playground"} and response.status_code in {200, 400, 405} and re.search(r"graphql", text, re.IGNORECASE):
        hits.append("GraphQL")
    return sorted(set(hits))


def check_api_exposure(url: str) -> dict[str, Any]:
    name = "API / debug exposure"
    try:
        base = url.rstrip("/")
        baseline = get_soft404_baseline(base)
        paths = API_PATHS_EXTENDED if cfg.profile == "extended" else API_PATHS_SAFE
        hits = []
        for path in paths:
            res = fetch_with_policy(base + path)
            if res.get("leak"):
                hits.append({"path": path, "issue": "redirect leak", "target": res.get("leak")})
                continue
            r = res.get("response")
            if r is None or looks_like_soft404(res, baseline):
                continue
            labels = _classify_api_response(path, r)
            if labels:
                hits.append({"path": path, "status": r.status_code, "types": labels, "content_type": r.headers.get("Content-Type", "")})
        if not hits:
            return finding(name, "info", "info", f"No common API documentation or debug endpoint exposure detected ({len(paths)} paths checked)")
        risk = "high" if any(any("debug" in x.lower() or "pprof" in x.lower() or "expvar" in x.lower() for x in item.get("types", [])) for item in hits) else "medium"
        return finding(name, "warn", risk, hits[:40], raw={"paths_checked": len(paths), "hits": hits[:40]}, finding_type="exposure")
    except Exception as e:
        return error_finding(name, e)
