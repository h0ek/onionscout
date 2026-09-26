from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from onionscout.checks.analytics import check_analytics_ids
from onionscout.checks.api import check_api_exposure
from onionscout.checks.cloud import check_infrastructure_correlation
from onionscout.checks.fingerprinting import check_browser_fingerprinting
from onionscout.checks.iframes import check_iframes_and_suspicious_js
from onionscout.checks.headers import check_security_headers
from onionscout.checks.metadata import analyze_comment_text
from onionscout.report import render_html_report
from onionscout.cli import _split_csv_values
from onionscout.history import diff_payloads, list_scans, save_scan


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = text.encode()
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


class AnalyzerTests(unittest.TestCase):
    def test_fingerprinting(self):
        bundle = {
            "sources": [{"source": "inline-script-1", "text": "new RTCPeerConnection({iceServers:[{urls:'stun:stun.example'}]}); new AudioContext(); canvas.getContext('2d').getImageData(0,0,1,1);"}],
            "home_text": "",
            "external_scripts": [],
        }
        result = check_browser_fingerprinting("http://example.onion", bundle)
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["risk"], "medium")
        self.assertIn("WebRTC", result["evidence"])
        self.assertIn("AudioContext", result["evidence"])
        self.assertIn("Canvas", result["evidence"])

    def test_analytics(self):
        bundle = {
            "sources": [{"source": "inline-script-1", "text": "gtag('config','G-ABCDEF12'); fbq('init','123456789');"}],
            "home_text": "",
            "external_scripts": [],
        }
        result = check_analytics_ids("http://example.onion", bundle)
        self.assertEqual(result["status"], "warn")
        types = {x["type"] for x in result["evidence"]}
        self.assertIn("Google Analytics 4", types)
        self.assertIn("Meta Pixel", types)

    def test_cloud(self):
        response = FakeResponse(headers={"CF-Ray": "abc-WAW"})
        bundle = {
            "response": response,
            "home_text": "https://bucket.s3.eu-central-1.amazonaws.com/file.js https://site.vercel.app/app.js",
            "sources": [],
            "external_scripts": [],
        }
        result = check_infrastructure_correlation("http://example.onion", bundle)
        self.assertEqual(result["status"], "warn")
        providers = {x["provider"] for x in result["evidence"]}
        self.assertIn("AWS S3", providers)
        self.assertIn("Vercel", providers)
        self.assertIn("Cloudflare", providers)

    def test_iframes_and_suspicious_js(self):
        bundle = {
            "home_text": "<iframe src='https://example.com/x' style='display:none'></iframe>",
            "sources": [{"source": "inline-script-1", "text": "eval(atob('QUJD'));"}],
            "external_scripts": [],
        }
        result = check_iframes_and_suspicious_js("http://example.onion", bundle)
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["finding_type"], "deanon")
        self.assertTrue(result["evidence"]["iframes"])
        self.assertTrue(result["evidence"]["javascript_indicators"])

    def test_api_exposure(self):
        def fake_fetch(url, *args, **kwargs):
            if url.endswith("/openapi.json"):
                return {"response": FakeResponse(text='{"openapi":"3.1.0"}', headers={"Content-Type": "application/json"}, json_data={"openapi": "3.1.0"}), "leak": None}
            return {"response": FakeResponse(status_code=404, text="not found"), "leak": None}

        with patch("onionscout.checks.api.get_soft404_baseline", return_value=None), patch("onionscout.checks.api.looks_like_soft404", return_value=False), patch("onionscout.checks.api.fetch_with_policy", side_effect=fake_fetch):
            result = check_api_exposure("http://example.onion")
        self.assertEqual(result["status"], "warn")
        self.assertTrue(any(x["path"] == "/openapi.json" for x in result["evidence"]))

    def test_existing_header_check_after_refactor(self):
        response = FakeResponse(headers={"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})
        with patch("onionscout.checks.headers.fetch_with_policy", return_value={"response": response, "leak": None}):
            result = check_security_headers("http://example.onion")
        self.assertIn(result["status"], {"ok", "warn"})
        self.assertEqual(result["name"], "Security headers")

    def test_existing_metadata_helper_after_refactor(self):
        result = analyze_comment_text(["contact admin@example.org", "backend 10.20.30.40", "token=abcdefghijk"] )
        self.assertIn("10.20.30.40", result["ips"])
        self.assertTrue(result["secret_candidates"])

    def test_existing_report_after_refactor(self):
        results = [{"name": "A", "status": "warn", "risk": "medium", "finding_type": "leak", "group": "metadata leak", "evidence": "test", "raw": None}]
        payload = {"summary": {}, "results": results}
        html = render_html_report("http://example.onion", results, payload)
        self.assertIn("onionscout", html.lower())
        self.assertIn("example.onion", html)


class HistoryTests(unittest.TestCase):
    def test_history_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "history.db")
            first = {
                "tool": "onionscout",
                "version": "0.4.1",
                "target": "http://example.onion",
                "summary": {"by_status": {"warn": 1}, "high_signal": []},
                "results": [{"name": "A", "status": "warn", "risk": "medium", "finding_type": "leak", "group": "metadata leak", "evidence": "one"}],
            }
            second = {
                "tool": "onionscout",
                "version": "0.4.1",
                "target": "http://example.onion",
                "summary": {"by_status": {"warn": 1}, "high_signal": []},
                "results": [{"name": "B", "status": "warn", "risk": "high", "finding_type": "deanon", "group": "de-anonymization", "evidence": "two"}],
            }
            scan_id = save_scan(first, db)
            self.assertEqual(scan_id, 1)
            rows = list_scans(first["target"], db)
            self.assertEqual(len(rows), 1)
            diff = diff_payloads(first, second)
            self.assertEqual(diff["new"], [])
            self.assertEqual(diff["resolved"], [])
            self.assertEqual({x["name"] for x in diff["unknown"]}, {"A", "B"})
            self.assertEqual(os.stat(db).st_mode & 0o777, 0o600)

    def test_custom_history_parent_permissions_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "existing"
            parent.mkdir(mode=0o755)
            os.chmod(parent, 0o755)
            db = parent / "history.db"
            payload = {"version": "0.4.1", "target": "http://example.onion", "summary": {}, "results": []}
            save_scan(payload, str(db))
            self.assertEqual(os.stat(parent).st_mode & 0o777, 0o755)
            self.assertEqual(os.stat(db).st_mode & 0o777, 0o600)

    def test_aliases(self):
        values = _split_csv_values("fingerprinting, api, cloud, analytics, iframes")
        self.assertEqual(values, {"fingerprinting-js", "api-exposure", "infrastructure", "analytics-ids", "iframes-js"})


if __name__ == "__main__":
    unittest.main()
