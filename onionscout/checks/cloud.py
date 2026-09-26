from __future__ import annotations

import re
from typing import Any, Optional

from ..findings import error_finding, finding
from .javascript import collect_javascript_sources

PROVIDER_PATTERNS = [
    ("AWS S3", re.compile(r"\b[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b", re.IGNORECASE)),
    ("AWS CloudFront", re.compile(r"\b[a-z0-9.-]+\.cloudfront\.net\b", re.IGNORECASE)),
    ("AWS API Gateway", re.compile(r"\b[a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)),
    ("AWS Lambda", re.compile(r"\b[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws\b", re.IGNORECASE)),
    ("AWS Cognito", re.compile(r"\bcognito-idp\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)),
    ("Azure App Service", re.compile(r"\b[a-z0-9.-]+\.azurewebsites\.net\b", re.IGNORECASE)),
    ("Azure Blob Storage", re.compile(r"\b[a-z0-9.-]+\.blob\.core\.windows\.net\b", re.IGNORECASE)),
    ("Azure CDN", re.compile(r"\b[a-z0-9.-]+\.azureedge\.net\b", re.IGNORECASE)),
    ("Google Cloud Run", re.compile(r"\b[a-z0-9.-]+\.run\.app\b", re.IGNORECASE)),
    ("Google App Engine", re.compile(r"\b[a-z0-9.-]+\.appspot\.com\b", re.IGNORECASE)),
    ("Google Cloud Storage", re.compile(r"\b(?:storage\.googleapis\.com|[a-z0-9.-]+\.storage\.googleapis\.com)\b", re.IGNORECASE)),
    ("Google Cloud Functions", re.compile(r"\b[a-z0-9.-]+\.cloudfunctions\.net\b", re.IGNORECASE)),
    ("Cloudflare Workers", re.compile(r"\b[a-z0-9.-]+\.workers\.dev\b", re.IGNORECASE)),
    ("Cloudflare Pages", re.compile(r"\b[a-z0-9.-]+\.pages\.dev\b", re.IGNORECASE)),
    ("Cloudflare R2", re.compile(r"\b[a-z0-9.-]+\.r2\.dev\b", re.IGNORECASE)),
    ("Fastly", re.compile(r"\b[a-z0-9.-]+\.(?:fastly\.net|fastlylb\.net)\b", re.IGNORECASE)),
    ("Akamai", re.compile(r"\b[a-z0-9.-]+\.(?:akamaized\.net|edgekey\.net|edgesuite\.net)\b", re.IGNORECASE)),
    ("Bunny CDN", re.compile(r"\b[a-z0-9.-]+\.b-cdn\.net\b", re.IGNORECASE)),
    ("DigitalOcean Spaces", re.compile(r"\b[a-z0-9.-]+\.digitaloceanspaces\.com\b", re.IGNORECASE)),
    ("DigitalOcean App Platform", re.compile(r"\b[a-z0-9.-]+\.ondigitalocean\.app\b", re.IGNORECASE)),
    ("Heroku", re.compile(r"\b[a-z0-9.-]+\.herokuapp\.com\b", re.IGNORECASE)),
    ("Vercel", re.compile(r"\b[a-z0-9.-]+\.vercel\.app\b", re.IGNORECASE)),
    ("Netlify", re.compile(r"\b[a-z0-9.-]+\.netlify\.app\b", re.IGNORECASE)),
]

HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-vercel-id": "Vercel",
    "x-vercel-cache": "Vercel",
    "x-served-by": "CDN/proxy",
}


def check_infrastructure_correlation(url: str, bundle: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    name = "Infrastructure correlation"
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
            for provider, rx in PROVIDER_PATTERNS:
                for m in rx.finditer(text):
                    hits.append({"provider": provider, "indicator": m.group(0), "source": source_name})
                    if len(hits) >= 100:
                        break
                if len(hits) >= 100:
                    break
            if len(hits) >= 100:
                break

        response = data.get("response")
        if response is not None:
            for key, value in response.headers.items():
                low = key.lower()
                if low in HEADER_HINTS:
                    hits.append({"provider": HEADER_HINTS[low], "indicator": f"{key}: {value}", "source": "response-header"})
            server = response.headers.get("Server", "")
            if "cloudflare" in server.lower():
                hits.append({"provider": "Cloudflare", "indicator": f"Server: {server}", "source": "response-header"})

        unique = []
        seen = set()
        for item in hits:
            key = (item["provider"], item["indicator"], item["source"])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        if not unique:
            return finding(name, "info", "info", "No common cloud/CDN infrastructure correlation indicators detected")
        host_hits = [x for x in unique if x["source"] != "response-header"]
        risk = "medium" if host_hits else "low"
        return finding(name, "warn", risk, unique[:60], raw={"count": len(unique)}, finding_type="deanon")
    except Exception as e:
        return error_finding(name, e)
