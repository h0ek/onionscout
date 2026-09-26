from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .core import (
    ASSET_EXT_SKIP,
    _get_home_fingerprint,
    _looks_like_index_redirect_or_soft404,
    _norm_url,
    cfg,
    fetch_with_policy,
    get_soft404_baseline,
    html_extract,
    same_onion_host,
)
from .findings import error_finding, finding
from .checks.metadata import indicators_from_urls

def crawl_links(base_url: str, max_urls: int = 80, depth: int = 1) -> list[str]:
    from collections import deque
    base = base_url.rstrip("/")
    home_fp = _get_home_fingerprint(base)
    soft404_baseline = get_soft404_baseline(base)
    start_urls = [base + "/", base + "/robots.txt", base + "/sitemap.xml"]

    q = deque((u, 0) for u in start_urls)
    seen = set()
    out = []

    max_requests = max(3, max_urls + 3)
    requests = 0
    while q and len(out) < max_urls and requests < max_requests:
        current, d = q.popleft()
        if current in seen:
            continue
        seen.add(current)
        if not same_onion_host(base, current):
            continue
        if ASSET_EXT_SKIP.search(urlparse(current).path or ""):
            continue

        requests += 1
        try:
            result = fetch_with_policy(current)
            if result.get("leak"):
                continue
            r = result.get("response")
            if r is None:
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if r.status_code != 200 or ("html" not in ct and "xhtml" not in ct):
                continue
            is_homepage = current.rstrip("/") == base.rstrip("/")
            if not is_homepage and _looks_like_index_redirect_or_soft404(result, soft404_baseline, home_fp):
                continue
            out.append(current)
            if d >= depth:
                continue

            parser = html_extract(r.text or "")
            hrefs = parser.anchor_hrefs + [href for _, href in parser.link_hrefs] + parser.script_srcs + parser.img_srcs
            for href in hrefs:
                full = _norm_url(result.get("final_url") or current, href)
                if not full or not same_onion_host(base, full):
                    continue
                if full not in seen and len(q) < max_urls * 4:
                    q.append((full, d + 1))
        except Exception:
            continue
    return out

def crawl_finding(url: str) -> tuple[dict[str, Any], list[str]]:
    name = "Crawl links"
    if cfg.no_crawl:
        return finding(name, "info", "info", "Skipped (--no-crawl)"), []
    try:
        urls = crawl_links(url, max_urls=cfg.crawl_max_urls, depth=cfg.crawl_depth)
        return finding(name, "ok", "info", f"Collected {len(urls)} URLs (depth={cfg.crawl_depth}, max={cfg.crawl_max_urls})", raw={"count": len(urls), "urls": urls[:100]}), urls
    except Exception as e:
        return error_finding(name, e), []

def indicator_finding(urls: list[str]) -> dict[str, Any]:
    name = "Indicators (emails/crypto)"
    if not urls:
        return finding(name, "info", "info", "No crawled URLs to analyze")
    try:
        ind = indicators_from_urls(urls)
        return finding(name, "info", "low", ind if any(ind.values()) else "No indicators found", raw=ind)
    except Exception as e:
        return error_finding(name, e)
