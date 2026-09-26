from __future__ import annotations

import io
import zipfile
import xml.etree.ElementTree as ET

import re
from typing import Any
from urllib.parse import urlparse

from ..core import (
    BTC_RE,
    DOCUMENT_EXT_RE,
    DOCUMENT_METADATA_MAX_BYTES,
    DOCUMENT_METADATA_RE,
    EMAIL_RE,
    ETH_RE,
    ICON_COMMENT_RE,
    IMAGE_EXT_RE,
    IMAGE_METADATA_MARKERS,
    IMAGE_METADATA_MAX_BYTES,
    IMAGE_METADATA_MAX_IMAGES,
    JS_SCAN_MAX_BYTES,
    IPV4_RE,
    LINUX_PATH_RE,
    MAILTO_RE,
    OBF_EMAIL_RE,
    PLACEHOLDER_EMAIL_DOMAINS,
    SECRET_PATTERNS,
    URL_LITERAL_RE,
    WINDOWS_PATH_RE,
    XMR_RE,
    _is_clearnet,
    _is_onion,
    _looks_like_html,
    _resolve_candidates,
    _resolve_literal_url,
    cfg,
    fetch_with_policy,
    html_extract,
    is_valid_ipv4,
    same_onion_host,
)
from ..findings import error_finding, finding, no_response_finding

def analyze_comment_text(comments: list[str]) -> dict[str, Any]:
    joined = "\n".join(comments)
    ips = sorted(set(ip for ip in IPV4_RE.findall(joined) if is_valid_ipv4(ip)))
    urls = sorted(set(SECRET_PATTERNS["url"].findall(joined)))
    secret_hits = []

    for pname, rx in SECRET_PATTERNS.items():
        if pname == "url":
            continue
        for m in rx.finditer(joined):
            val = m.group(0)
            if len(val) > 120:
                val = val[:120] + "..."
            secret_hits.append({"type": pname, "match": val})

    boring = {"-", "--", "\u2014", "so meta", "title", "styles", "rss", "async scripts"}
    interesting = []
    for c in comments:
        clean = c.strip()
        if not clean or clean.lower() in boring:
            continue
        if len(clean) == 1 and not clean.isalnum():
            continue
        interesting.append(clean)

    return {
        "comments_preview": interesting[:30],
        "ips": ips[:30],
        "urls": urls[:50],
        "secret_candidates": secret_hits[:30],
        "total_comments": len(comments),
    }

def check_comments(url: str) -> dict[str, Any]:
    name = "Comments in code"
    try:
        data = fetch_with_policy(url)
        if data.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {data['leak']}", raw=data, finding_type="deanon")
        r = data.get("response")
        if r is None:
            return finding(name, "warn", "low", f"No response ({data.get('error', 'unknown error')})", raw=data)
        comments = []
        for c in ICON_COMMENT_RE.findall(r.text or ""):
            for line in c.splitlines():
                line = line.strip()
                if line:
                    comments.append(line)
        if not comments:
            return finding(name, "info", "info", "No comments in code")

        analysis = analyze_comment_text(comments)
        has_secret = bool(analysis["secret_candidates"])
        has_ip_or_url = bool(analysis["ips"] or analysis["urls"])
        status = "warn" if has_secret or has_ip_or_url or analysis["comments_preview"] else "info"
        risk = "high" if has_secret else ("medium" if has_ip_or_url else "low")
        return finding(name, status, risk, analysis, raw=analysis, finding_type="leak")
    except Exception as e:
        return error_finding(name, e)

def _image_metadata_hits(raw: bytes) -> dict[str, Any]:
    markers = []
    for marker in IMAGE_METADATA_MARKERS:
        if marker.lower() in (raw or b"").lower():
            try:
                markers.append(marker.decode("ascii", errors="ignore"))
            except Exception:
                markers.append(repr(marker))

    decoded = (raw or b"")[:IMAGE_METADATA_MAX_BYTES].decode("latin-1", errors="ignore")
    urls = sorted(set(re.findall(r'https?://[^\s\'"<>\x00]{4,160}', decoded, re.IGNORECASE)))
    ips = sorted(set(ip for ip in IPV4_RE.findall(decoded) if is_valid_ipv4(ip)))
    gps = any(x.lower().startswith("gps") or "gps" in x.lower() for x in markers)
    return {"markers": sorted(set(markers)), "urls": urls[:30], "ips": ips[:30], "gps_hint": gps}

def check_image_metadata(url: str) -> dict[str, Any]:
    name = "Image metadata"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak → {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
        parser = html_extract(r.text or "")
        images = []
        for src in parser.img_srcs:
            full = _resolve_literal_url(url, src)
            if not full:
                continue
            if _is_clearnet(full):
                images.append({"url": full, "issue": "clearnet image resource"})
                continue
            if not same_onion_host(url, full):
                images.append({"url": full, "issue": "cross-onion image resource"})
                continue
            if not IMAGE_EXT_RE.search(urlparse(full).path or ""):
                continue
            images.append({"url": full})

        hits = []
        raw_hits = []
        checked = 0
        for item in images[:IMAGE_METADATA_MAX_IMAGES]:
            full = item["url"]
            if item.get("issue"):
                hits.append(f"{full}: {item['issue']}")
                raw_hits.append(item)
                continue
            img_res = fetch_with_policy(full)
            ir = img_res.get("response")
            if ir is None or ir.status_code != 200 or not ir.content:
                continue
            checked += 1
            raw = (ir.content or b"")[:IMAGE_METADATA_MAX_BYTES]
            meta = _image_metadata_hits(raw)
            if meta["markers"] or meta["urls"] or meta["ips"]:
                hits.append(f"{full}: metadata markers={meta['markers'][:8]}, urls={len(meta['urls'])}, ips={len(meta['ips'])}")
                raw_hits.append({"url": full, **meta})

        if raw_hits:
            risk = "high" if any(x.get("gps_hint") or x.get("ips") for x in raw_hits if isinstance(x, dict)) else "medium"
            return finding(name, "warn", risk, hits, raw={"checked": checked, "hits": raw_hits}, finding_type="leak")
        return finding(name, "info", "info", f"No obvious image metadata leaks detected (checked={checked})")
    except Exception as e:
        return error_finding(name, e)

def check_robots_sitemap(url: str) -> dict[str, Any]:
    name = "Robots & sitemap"
    try:
        base = url.rstrip("/")
        out = []
        leaks = []
        raw = []
        for path in ("/robots.txt", "/sitemap.xml"):
            res = fetch_with_policy(f"{base}{path}")
            if res.get("leak"):
                leaks.append(f"{path} redirect leak → {res['leak']}")
                raw.append({"path": path, "leak": res.get("leak")})
                continue
            r = res.get("response")
            if r is None or r.status_code != 200 or not (r.content or b""):
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if path.endswith("robots.txt") and _looks_like_html(r.content or b"", ct):
                continue
            text = r.text or ""
            urls = sorted(set(_resolve_literal_url(base, u) for u in re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE)))
            urls = [u for u in urls if u and "sitemaps.org/schemas/" not in u]
            clear_urls = [u for u in urls if _is_clearnet(u)]
            cross_onion_urls = [u for u in urls if _is_onion(u) and not same_onion_host(base, u)]
            if clear_urls:
                leaks.append(f"{path} clearnet URLs: " + " | ".join(clear_urls[:20]))
            if cross_onion_urls:
                leaks.append(f"{path} cross-onion URLs: " + " | ".join(cross_onion_urls[:20]))
            if path.endswith("robots.txt"):
                lines = [l for l in text.splitlines() if l.lower().startswith(("disallow:", "allow:", "sitemap:"))]
                if lines:
                    out.append("/robots.txt entries:\n" + "\n".join(lines[:100]))
                    raw.append({"path": path, "lines": lines[:100], "clearnet_urls": clear_urls, "cross_onion_urls": cross_onion_urls})
            else:
                try:
                    root = ET.fromstring((r.content or b"")[:DOCUMENT_METADATA_MAX_BYTES])
                    locs = [node.text.strip() for node in root.iter() if node.tag.split("}")[-1] == "loc" and node.text and node.text.strip()]
                except ET.ParseError:
                    locs = re.findall(r"<loc>([^<]+)</loc>", text, re.IGNORECASE)
                if locs:
                    out.append("/sitemap.xml locs:\n" + "\n".join(locs[:100]))
                    raw.append({"path": path, "locs": locs[:100], "clearnet_urls": clear_urls, "cross_onion_urls": cross_onion_urls})
        if leaks:
            return finding(name, "warn", "high", leaks + out, raw=raw, finding_type="deanon")
        if out:
            return finding(name, "info", "low", out, raw=raw)
        return finding(name, "info", "info", "No robots.txt or sitemap.xml entries found")
    except Exception as e:
        return error_finding(name, e)

def _json_ld_blocks(html: str) -> list[str]:
    blocks = []
    for m in re.finditer(r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>([\s\S]*?)</script>", html or "", re.IGNORECASE):
        body = (m.group(1) or "").strip()
        if body:
            blocks.append(body[:JS_SCAN_MAX_BYTES])
    return blocks[:10]

def _urls_from_json_like_text(base_url: str, text: str) -> list[str]:
    urls = []
    for m in URL_LITERAL_RE.finditer(text or ""):
        full = _resolve_literal_url(base_url, m.group("url"))
        if full:
            urls.append(full)
    return sorted(set(urls))

def check_meta_and_link_leaks(url: str) -> dict[str, Any]:
    name = "Canonical / OG / RSS / JSON-LD leaks"
    try:
        res = fetch_with_policy(url)
        if res.get("leak"):
            return finding(name, "fail", "high", f"Redirect leak \u2192 {res['leak']}", raw=res, finding_type="deanon")
        r = res.get("response")
        if r is None:
            return no_response_finding(name, res)
        body = r.text or ""
        p = html_extract(body)
        rss_candidates = []
        for rel, href in p.link_hrefs:
            if "alternate" in rel or "feed" in rel:
                full = _resolve_literal_url(url, href)
                if full:
                    rss_candidates.append(full)
        buckets = {
            "canonical": _resolve_candidates(url, p.canonical_urls),
            "alternate": _resolve_candidates(url, p.alternate_urls),
            "rss_atom": rss_candidates,
            "preconnect": _resolve_candidates(url, p.preconnect_urls),
            "prefetch": _resolve_candidates(url, p.prefetch_urls),
            "preload": _resolve_candidates(url, p.preload_urls),
            "og": _resolve_candidates(url, p.og_urls),
            "twitter": _resolve_candidates(url, p.twitter_urls),
            "json_ld": [u for block in _json_ld_blocks(body) for u in _urls_from_json_like_text(url, block) if urlparse(u).hostname not in {"schema.org", "www.schema.org", "www.w3.org", "w3.org"}],
        }
        hits = []
        raw = {}
        for k, vals in buckets.items():
            vals = sorted(set(vals))
            clear = [v for v in vals if _is_clearnet(v)]
            cross_onion = [v for v in vals if _is_onion(v) and not same_onion_host(url, v)]
            if vals:
                raw[k] = {"all": vals[:80], "clearnet": clear[:40], "cross_onion": cross_onion[:40]}
            if clear:
                hits.append(f"{k} clearnet: " + " | ".join(clear[:20]))
            if cross_onion:
                hits.append(f"{k} cross-onion: " + " | ".join(cross_onion[:20]))
        if hits:
            high = any(k != "json_ld" and (v.get("clearnet") or v.get("cross_onion")) for k, v in raw.items())
            return finding(name, "warn", "medium" if high else "low", hits, raw=raw, finding_type="leak")
        return finding(name, "info", "info", "No clearnet or cross-onion leaks in canonical/OG/RSS/JSON-LD metadata", raw=raw)
    except Exception as e:
        return error_finding(name, e)

def _document_scan_limit() -> int:
    return 12 if cfg.profile == "extended" else 6

def _collect_document_links(base_url: str, page_urls: list[str]) -> tuple[list[str], list[str]]:
    docs = set()
    external = set()
    pages = [base_url] + [u for u in page_urls if same_onion_host(base_url, u)]
    for page_url in pages[:25]:
        try:
            res = fetch_with_policy(page_url)
            r = res.get("response")
            if r is None or r.status_code != 200:
                continue
            ct = (r.headers.get("Content-Type", "") or "").lower()
            if "html" not in ct and "xhtml" not in ct:
                continue
            parser = html_extract(r.text or "")
            candidates = parser.anchor_hrefs + [href for _, href in parser.link_hrefs]
            for href in candidates:
                full = _resolve_literal_url(page_url, href)
                if not full:
                    continue
                if not DOCUMENT_EXT_RE.search(urlparse(full).path or full):
                    continue
                if _is_clearnet(full) or (_is_onion(full) and not same_onion_host(base_url, full)):
                    external.add(full)
                elif same_onion_host(base_url, full):
                    docs.add(full)
        except Exception:
            continue
    return sorted(docs), sorted(external)

def _document_metadata_hits(raw: bytes) -> dict[str, Any]:
    blob = (raw or b"")[:DOCUMENT_METADATA_MAX_BYTES]
    text = blob.decode("latin-1", errors="ignore")
    if zipfile.is_zipfile(io.BytesIO(blob)):
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                parts = []
                for name in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
                    if name not in archive.namelist():
                        continue
                    entry = archive.getinfo(name)
                    if entry.file_size > 128_000:
                        continue
                    part = archive.read(name)
                    try:
                        root = ET.fromstring(part)
                        parts.extend(str(element.text) for element in root.iter() if element.text)
                    except ET.ParseError:
                        parts.append(part.decode("utf-8", errors="replace"))
                text += "\n" + "\n".join(parts)
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
            pass
    urls = sorted(set(u for u in re.findall(r"https?://[^\s'\"<>\x00]{4,180}", text, re.IGNORECASE) if _is_clearnet(u)))
    onions = sorted(set(u for u in re.findall(r"https?://[^\s'\"<>\x00]*\.onion[^\s'\"<>\x00]{0,120}", text, re.IGNORECASE)))
    ips = sorted(set(ip for ip in IPV4_RE.findall(text) if is_valid_ipv4(ip)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    metadata = []
    for m in DOCUMENT_METADATA_RE.finditer(text):
        label = m.group(0).strip()
        label = re.sub(r"\s+", " ", label)
        metadata.append(label[:180])
    windows_paths = sorted(set(WINDOWS_PATH_RE.findall(text)))[:20]
    linux_paths = sorted(set(LINUX_PATH_RE.findall(text)))[:20]
    return {
        "metadata": sorted(set(metadata))[:40],
        "clearnet_urls": urls[:40],
        "onion_urls": onions[:40],
        "ips": ips[:40],
        "emails": emails[:40],
        "windows_paths": windows_paths,
        "linux_paths": linux_paths,
    }

def check_document_metadata(url: str, crawled_urls: list[str]) -> dict[str, Any]:
    name = "Document metadata"
    try:
        docs, external = _collect_document_links(url, crawled_urls)
        hits = []
        raw_hits = []
        skipped = []
        checked = 0
        for ext in external[:30]:
            hits.append(f"external document link: {ext}")
            raw_hits.append({"url": ext, "issue": "external document link"})
        for doc_url in docs[:_document_scan_limit()]:
            head = fetch_with_policy(doc_url, method="HEAD")
            hr = head.get("response")
            if hr:
                size = int(hr.headers.get("Content-Length") or 0)
                if size and size > DOCUMENT_METADATA_MAX_BYTES * 4:
                    skipped.append({"url": doc_url, "skipped": "too large", "size": size})
                    continue
            res = fetch_with_policy(doc_url)
            if res.get("leak"):
                hits.append(f"{doc_url}: redirect leak \u2192 {res['leak']}")
                raw_hits.append({"url": doc_url, "leak": res.get("leak")})
                continue
            r = res.get("response")
            if r is None or r.status_code != 200 or not r.content:
                continue
            checked += 1
            meta = _document_metadata_hits(r.content)
            interesting = any(meta[k] for k in ("metadata", "clearnet_urls", "ips", "emails", "windows_paths", "linux_paths"))
            if interesting:
                summary = []
                for key in ("metadata", "clearnet_urls", "ips", "emails", "windows_paths", "linux_paths"):
                    if meta[key]:
                        summary.append(f"{key}={len(meta[key])}")
                hits.append(f"{doc_url}: " + ", ".join(summary))
                raw_hits.append({"url": doc_url, **meta})
        if raw_hits:
            high = any(x.get("clearnet_urls") or x.get("ips") or x.get("windows_paths") or x.get("linux_paths") for x in raw_hits if isinstance(x, dict))
            return finding(name, "warn", "high" if high else "medium", hits[:80] or raw_hits[:20], raw={"checked": checked, "document_links": docs[:80], "external_links": external[:80], "skipped": skipped, "hits": raw_hits}, finding_type="leak")
        return finding(name, "info", "info", f"No document metadata leaks detected (links={len(docs)}, checked={checked})", raw={"document_links": docs[:80], "external_links": external[:80], "skipped": skipped})
    except Exception as e:
        return error_finding(name, e)

def normalize_obfuscated_email(value: str) -> Optional[str]:
    raw = (value or "").strip()
    raw = re.sub(r"^mailto:", "", raw, flags=re.IGNORECASE)
    raw = raw.split("?", 1)[0].strip()
    if not raw:
        return None

    candidate = raw
    replacements = [
        (r"\s*(?:\(|\[|\{)\s*at\s*(?:\)|\]|\})\s*", "@"),
        (r"\s+at\s+", "@"),
        (r"\s*(?:\(|\[|\{)\s*dot\s*(?:\)|\]|\})\s*", "."),
        (r"\s+dot\s+", "."),
    ]

    for pattern, repl in replacements:
        candidate = re.sub(pattern, repl, candidate, flags=re.IGNORECASE)

    candidate = candidate.replace(" ", "")
    if EMAIL_RE.fullmatch(candidate):
        return candidate

    return None

def extract_obfuscated_emails(text: str) -> list[str]:
    found = set()

    for m in MAILTO_RE.finditer(text or ""):
        v = normalize_obfuscated_email(m.group(1))
        if v:
            found.add(v)

    for m in OBF_EMAIL_RE.finditer(text or ""):
        raw = m.group(0)
        v = normalize_obfuscated_email(raw)
        if v:
            found.add(v)

    return sorted(found)

def split_placeholder_emails(emails: set[str]) -> tuple[set[str], set[str]]:
    real = set()
    placeholders = set()

    for email in emails:
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if domain in PLACEHOLDER_EMAIL_DOMAINS:
            placeholders.add(email)
        else:
            real.add(email)

    return real, placeholders

def extract_indicators_from_text(text: str) -> dict[str, list[str]]:
    t = text or ""

    normal_emails = set(EMAIL_RE.findall(t))
    obfuscated_emails = set(extract_obfuscated_emails(t))
    all_emails = normal_emails | obfuscated_emails
    real_emails, placeholder_emails = split_placeholder_emails(all_emails)

    return {
        "emails": sorted(real_emails),
        "obfuscated_emails": sorted(obfuscated_emails - placeholder_emails),
        "placeholder_emails": sorted(placeholder_emails),
        "btc": sorted(set(BTC_RE.findall(t))),
        "eth": sorted(set(ETH_RE.findall(t))),
        "xmr": sorted(set(XMR_RE.findall(t))),
    }

def indicators_from_urls(urls: list[str]) -> dict[str, list[str]]:
    agg = {
        "emails": set(),
        "obfuscated_emails": set(),
        "placeholder_emails": set(),
        "btc": set(),
        "eth": set(),
        "xmr": set(),
    }

    for u in urls:
        try:
            r = fetch_with_policy(u).get("response")
            if r is None or r.status_code != 200:
                continue

            ct = (r.headers.get("Content-Type", "") or "").lower()
            if "html" not in ct and "xhtml" not in ct:
                continue

            ind = extract_indicators_from_text(r.text or "")
            for k in agg:
                agg[k].update(ind.get(k, []))
        except Exception:
            continue

    return {k: sorted(v) for k, v in agg.items()}
