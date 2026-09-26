from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import requests

from onionscout import core
from onionscout.checks import api, files, headers, javascript, metadata, ssh, web
from onionscout.crawler import crawl_links
from onionscout.findings import make_json_safe
from onionscout.history import diff_payloads, target_key


KEY = bytes(range(32))
HOST = base64.b32encode(KEY + hashlib.sha3_256(b".onion checksum" + KEY + b"\x03").digest()[:2] + b"\x03").decode().lower() + ".onion"
BASE = "http://" + HOST


def response(text="", status=200, headers_dict=None, url=BASE):
    r = requests.Response()
    r.status_code = status
    r._content = text.encode() if isinstance(text, str) else text
    r._content_consumed = True
    r.headers.update({"Content-Type": "text/html"})
    r.headers.update(headers_dict or {})
    r.url = url
    r.encoding = "utf-8"
    return r


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.saved = core.cfg
        self.saved_session = core.session
        core.cfg = core.Config(target_host=HOST, target_port=None, retries=0, sleep=0)
        core.session = requests.Session()
        core.configure_tor_proxy("127.0.0.1", 9050)
        core.rebuild_retry_adapter()

    def tearDown(self):
        core.cfg = self.saved
        core.session = self.saved_session

    def test_proxy_environment_ignored(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:8888", "HTTPS_PROXY": "http://127.0.0.1:8888", "ALL_PROXY": "http://127.0.0.1:8888", "NO_PROXY": "*"}, clear=True):
            settings = core.session.merge_environment_settings(BASE, {}, False, True, None)
            self.assertFalse(core.session.trust_env)
            self.assertEqual(settings["proxies"].get("http"), "socks5h://127.0.0.1:9050")
            with patch.object(core, "_request_once", return_value=response()) as fetch:
                core.request("GET", BASE)
                self.assertEqual(fetch.call_count, 1)

    def test_proxy_required_no_direct_fallback(self):
        core.session.proxies.clear()
        with patch.object(core.session, "request") as fetch:
            with self.assertRaises(RuntimeError):
                core.request("GET", BASE)
            fetch.assert_not_called()

    def test_non_target_and_port_blocked(self):
        for url in ("http://outside.example/", "http://" + "a" * 56 + ".onion/", BASE + ":8080/", "http://check.torproject.org/"):
            with self.subTest(url=url), patch.object(core.session, "request") as fetch:
                with self.assertRaises(ValueError):
                    core.request("GET", url)
                fetch.assert_not_called()

    def test_failed_origin_probe_not_selected(self):
        with patch.object(core, "probe_origin", return_value={"ok": False, "final_url": "http://outside.example/", "reason": "blocked"}):
            selected, _ = core.choose_working_origin(BASE, "http")
        self.assertEqual(selected, BASE)

    def test_redirect_to_clearnet_does_not_connect(self):
        with patch.object(core, "request", return_value=response(status=302, headers_dict={"Location": "http://outside.example/"})) as fetch:
            result = core.fetch_with_policy(BASE)
        self.assertEqual(result["error_kind"], "clearnet_blocked")
        self.assertEqual(fetch.call_count, 1)

    def test_four_hundred_and_five_hundred_are_responses(self):
        for status in (404, 500):
            with self.subTest(status=status), patch.object(files, "_get_home_fingerprint", return_value=None), patch.object(files, "fetch_with_policy", return_value={"response": response("Fatal error /var/www/private.php", status), "leak": None}):
                result = files.check_error_page_fingerprints(BASE)
                self.assertNotIn("No response", str(result.get("evidence")))

    def test_no_retry_means_one_attempt(self):
        self.assertEqual(core.session.get_adapter(BASE).max_retries.total, 0)
        with patch.object(core, "_request_once", return_value=response(status=503)) as fetch:
            self.assertEqual(core.request("GET", BASE).status_code, 503)
            self.assertEqual(fetch.call_count, 1)

    def test_tls_fallback_zero_retries_and_mirror_strict(self):
        with patch.object(core, "_request_once", side_effect=[requests.exceptions.SSLError("self-signed certificate"), response()]) as fetch:
            self.assertEqual(core.request("GET", BASE.replace("http:", "https:")).status_code, 200)
            self.assertEqual(fetch.call_count, 2)
            self.assertFalse(core.cfg.insecure_https)
            self.assertFalse(fetch.call_args.args[3])
        core.cfg.clearnet_url = "https://example.org"
        with patch.object(core, "_request_once", return_value=response()) as fetch:
            core.request("GET", "https://example.org")
            self.assertTrue(fetch.call_args.args[3])

    def test_body_limit_during_stream(self):
        core.cfg.max_body_bytes = 1024
        fake = response(b"x" * 3000)
        with patch.object(core.session, "request", return_value=fake):
            with self.assertRaises(core.DownloadLimitExceeded):
                core.request("GET", BASE)

    def test_request_budget(self):
        core.cfg.max_requests = 1
        with patch.object(core.session, "request", return_value=response()):
            core.request("GET", BASE)
            with self.assertRaises(core.RequestBudgetExceeded):
                core.request("GET", BASE)

    def test_cookie_value_not_a_flag_and_is_redacted(self):
        data = {"response": response(headers_dict={"Set-Cookie": "sid=securehttponly; SameSite=Lax"}), "leak": None}
        with patch.object(headers, "fetch_with_policy", return_value=data):
            result = headers.analyze_set_cookie(BASE)
        self.assertEqual(result["status"], "warn")
        self.assertIn("missing Secure", str(result["evidence"]))
        self.assertNotIn("securehttponly", str(result))
        self.assertNotIn("TOPSECRET", str(make_json_safe(response(headers_dict={"Set-Cookie": "sid=TOPSECRET"}))))

    def test_svg_not_html(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'
        self.assertFalse(core._looks_like_html(svg, "image/svg+xml"))
        self.assertTrue(web._favicon_content_ok(svg, "image/svg+xml"))

    def test_sitemap_namespace(self):
        text = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + BASE + '/private</loc></url></urlset>'
        with patch.object(metadata, "fetch_with_policy", side_effect=[{"response": response("", 404), "leak": None}, {"response": response(text, headers_dict={"Content-Type": "application/xml"}), "leak": None}]):
            result = metadata.check_robots_sitemap(BASE)
        self.assertIn("/private", str(result["evidence"]))
        self.assertNotIn("clearnet URLs", str(result["evidence"]))

    def test_soft404_dynamic_catchall_is_detected_and_cached(self):
        core.cfg.soft404_cache = {}
        calls = []

        def fake_fetch(url, **kwargs):
            calls.append(url)
            token = url.rsplit("/", 1)[-1]
            body = f'<!doctype html><html><head><title>404 - Not Found</title></head><body><img src="/static/404.png"><h1>404</h1><p>Page {url} was not found.</p><span>request={token}123456789</span></body></html>'
            return {"response": response(body, 200, url=url), "leak": None, "final_url": url}

        with patch.object(core, "fetch_with_policy", side_effect=fake_fetch):
            baseline = core.get_soft404_baseline(BASE)
            cached = core.get_soft404_baseline(BASE)

        candidate_url = BASE + "/backup.zip"
        candidate = response('<!doctype html><html><head><title>404 - Not Found</title></head><body><img src="/static/404.png"><h1>404</h1><p>Page ' + candidate_url + ' was not found.</p><span>request=abcdef12345678901234567890</span></body></html>', 200, url=candidate_url)
        self.assertTrue(baseline["stable"])
        self.assertIs(baseline, cached)
        self.assertEqual(len(calls), 2)
        self.assertTrue(core.looks_like_soft404(candidate, baseline))

    def test_soft404_does_not_hide_distinct_real_page(self):
        samples = [
            core._soft404_signature(response('<html><head><title>404 - Not Found</title></head><body><h1>404</h1><p>missing page</p></body></html>', 200, url=BASE + "/missing-a")),
            core._soft404_signature(response('<html><head><title>404 - Not Found</title></head><body><h1>404</h1><p>missing page</p></body></html>', 200, url=BASE + "/missing-b")),
        ]
        baseline = {"stable": True, "samples": samples}
        admin = response('<html><head><title>Admin Login</title></head><body><form><input name="username"><input type="password"></form></body></html>', 200, url=BASE + "/admin")
        self.assertFalse(core.looks_like_soft404(admin, baseline))

    def test_backup_soft404_is_suppressed(self):
        samples = [
            core._soft404_signature(response('<html><title>Not Found</title><body><h1>404</h1><p>missing</p></body></html>', 200, url=BASE + "/missing-a")),
            core._soft404_signature(response('<html><title>Not Found</title><body><h1>404</h1><p>missing</p></body></html>', 200, url=BASE + "/missing-b")),
        ]
        baseline = {"stable": True, "samples": samples}
        miss = response('<html><title>Not Found</title><body><h1>404</h1><p>missing</p></body></html>', 200, url=BASE + "/backup.zip")
        with patch.object(files, "_backup_paths_for_profile", return_value=["/backup.zip"]), patch.object(files, "get_soft404_baseline", return_value=baseline), patch.object(files, "fetch_with_policy", return_value={"response": miss, "leak": None}):
            result = files.check_backup_archives(BASE)
        self.assertEqual(result["status"], "info")
        self.assertIn("No backup/archive files detected", str(result["evidence"]))

    def test_api_and_well_known_soft404_are_suppressed(self):
        samples = [
            core._soft404_signature(response('<html><title>Page Not Found</title><body><h1>404</h1><p>GraphQL page not found</p></body></html>', 200, url=BASE + "/missing-a")),
            core._soft404_signature(response('<html><title>Page Not Found</title><body><h1>404</h1><p>GraphQL page not found</p></body></html>', 200, url=BASE + "/missing-b")),
        ]
        baseline = {"stable": True, "samples": samples}
        miss = response('<html><title>Page Not Found</title><body><h1>404</h1><p>GraphQL page not found</p></body></html>', 200, url=BASE + "/graphql")
        with patch.object(api, "get_soft404_baseline", return_value=baseline), patch.object(api, "fetch_with_policy", return_value={"response": miss, "leak": None}):
            api_result = api.check_api_exposure(BASE)
        with patch.object(files, "get_soft404_baseline", return_value=baseline), patch.object(files, "fetch_with_policy", return_value={"response": miss, "leak": None}):
            well_known_result = files.check_well_known(BASE)
        self.assertEqual(api_result["status"], "info")
        self.assertEqual(well_known_result["status"], "info")
        self.assertIn("No .well-known endpoints found", str(well_known_result["evidence"]))

    def test_securitytxt_soft404_is_not_reported_as_invalid_file(self):
        samples = [
            core._soft404_signature(response('<html><title>Not Found</title><body><h1>404</h1></body></html>', 200, url=BASE + "/missing-a")),
            core._soft404_signature(response('<html><title>Not Found</title><body><h1>404</h1></body></html>', 200, url=BASE + "/missing-b")),
        ]
        baseline = {"stable": True, "samples": samples}
        miss = response('<html><title>Not Found</title><body><h1>404</h1></body></html>', 200, url=BASE + "/.well-known/security.txt")
        with patch.object(files, "get_soft404_baseline", return_value=baseline), patch.object(files, "fetch_with_policy", return_value={"response": miss, "leak": None}):
            result = files._fetch_security_txt(BASE, "/.well-known/security.txt")
        self.assertEqual(result["status"], "info")
        self.assertIn("soft-404", str(result["evidence"]))

    def test_crawler_relative_urls_and_budget(self):
        pages = {BASE + "/": '<a href="/docs/start/">start</a>', BASE + "/docs/start/": '<a href="child">child</a>', BASE + "/docs/start/child": "<p>ok</p>"}
        calls = []
        def fake_fetch(url, **kwargs):
            calls.append(url)
            return {"response": response(pages.get(url, ""), 200 if url in pages else 404, url=url), "leak": None, "final_url": url}
        with patch("onionscout.crawler._get_home_fingerprint", return_value=None), patch("onionscout.crawler.get_soft404_baseline", return_value=None), patch("onionscout.crawler.fetch_with_policy", side_effect=fake_fetch):
            urls = crawl_links(BASE, 20, 2)
        self.assertIn(BASE + "/docs/start/child", urls)
        self.assertLessEqual(len(calls), 23)

    def test_resources_base_iframe_srcset_css(self):
        vectors = ('<iframe src="https://example.org/x"></iframe>', '<img srcset="https://example.org/p.png 2x">', '<style>a{background:url(https://example.org/bg.png)}</style>', '<base href="https://example.org/"><script src="a.js"></script>')
        for html in vectors:
            with self.subTest(html=html), patch.object(javascript, "fetch_with_policy", return_value={"response": response(html), "leak": None, "final_url": BASE}):
                result = javascript.check_external_resources(BASE)
                self.assertEqual(result["risk"], "high", result)

    def test_csp_bare_host(self):
        with patch.object(headers, "fetch_with_policy", return_value={"response": response(headers_dict={"Content-Security-Policy": "script-src cdn.example.org"}), "leak": None}):
            result = headers.check_csp_related(BASE)
        self.assertEqual(result["status"], "warn")

    def test_csp_scheme_source_not_converted_to_fake_host(self):
        policy = "default-src 'self'; script-src 'self' https: https://cdn.example.org"
        with patch.object(headers, "fetch_with_policy", return_value={"response": response(headers_dict={"Content-Security-Policy": policy}), "leak": None}):
            result = headers.check_csp_related(BASE)
        evidence = str(result["evidence"])
        self.assertIn("https:", evidence)
        self.assertIn("https://cdn.example.org", evidence)
        self.assertNotIn("https://https:", evidence)

    def test_ssh_paramiko_failure_is_quiet_and_closes_transport(self):
        created = []

        class DummySocket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class DummyTransport:
            def __init__(self, sock):
                self.sock = sock
                self.log_channel = None
                self.closed = False
                self.banner_timeout = None
                created.append(self)

            def set_log_channel(self, channel):
                self.log_channel = channel

            def start_client(self, timeout=None):
                import logging
                logging.getLogger(self.log_channel).error("Error reading SSH protocol banner", exc_info=True)
                raise RuntimeError("Error reading SSH protocol banner")

            def close(self):
                self.closed = True

        sock = DummySocket()
        stderr = io.StringIO()
        with patch.object(ssh, "_make_tor_socket", return_value=sock), patch.object(ssh.paramiko, "Transport", DummyTransport), contextlib.redirect_stderr(stderr):
            result = ssh.check_ssh_fingerprint(BASE)
        self.assertEqual(result["status"], "info")
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(created[0].log_channel, "onionscout.paramiko.ssh")
        self.assertTrue(created[0].closed)

    def test_cors_wildcard_credentials_not_high(self):
        with patch.object(headers, "request", return_value=response(headers_dict={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})):
            self.assertNotEqual(headers.check_cors(BASE)["risk"], "high")

    def test_schema_org_context_not_high(self):
        with patch.object(metadata, "fetch_with_policy", return_value={"response": response('<script type="application/ld+json">{"@context":"https://schema.org"}</script>'), "leak": None}):
            self.assertNotEqual(metadata.check_meta_and_link_leaks(BASE)["risk"], "high")

    def test_docx_core_properties(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("docProps/core.xml", '<cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>AuditAuthor</dc:creator></cp:coreProperties>')
        self.assertIn("AuditAuthor", str(metadata._document_metadata_hits(buffer.getvalue())))

    def test_diff_unknown_on_timeout_and_scope_change(self):
        first = {"target": BASE, "config": {"profile": "safe"}, "results": [{"name": "Files", "status": "warn", "risk": "high", "evidence": "exposed"}]}
        second = {"target": BASE, "config": {"profile": "safe"}, "results": [{"name": "Files", "status": "error", "risk": "info", "evidence": "No response"}]}
        result = diff_payloads(first, second)
        self.assertFalse(result["resolved"])
        self.assertEqual(result["unknown"][0]["name"], "Files")
        self.assertNotEqual(target_key(BASE), target_key(BASE.replace("http:", "https:")))

    def test_onion_v3_checksum_validation(self):
        self.assertEqual(core.normalize_url(BASE), BASE)
        with self.assertRaises(ValueError):
            core.normalize_url("http://" + "a" * 56 + ".onion")


    def test_explicit_socks_used_in_transport_even_with_env_proxy(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:8888", "HTTPS_PROXY": "http://127.0.0.1:8888", "NO_PROXY": "*"}):
            with patch.object(core.session, "request", return_value=response()) as fetch:
                core.request("GET", BASE)
            settings = fetch.call_args.kwargs
            self.assertFalse(core.session.trust_env)
            self.assertEqual(settings["proxies"]["http"], "socks5h://127.0.0.1:9050")
            self.assertFalse(settings["allow_redirects"])
            self.assertTrue(settings["stream"])

    def test_response_cache_is_bounded_and_skips_cookies(self):
        import time
        core.cfg.response_cache = {}
        core.cfg.started_at = time.monotonic()
        with patch.object(core, "_request_once", return_value=response("ok", headers_dict={"Set-Cookie": "sid=sensitive"})) as fetch:
            core.request("GET", BASE)
            core.request("GET", BASE)
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(len(core.cfg.response_cache), 0)
        for i in range(40):
            with patch.object(core, "_request_once", return_value=response("ok")):
                core.request("GET", BASE + "/" + str(i))
        self.assertLessEqual(len(core.cfg.response_cache), 32)

    def test_advertised_http_methods_are_not_confirmed_exposure(self):
        with patch.object(files, "fetch_with_policy", side_effect=[
            {"response": response("", status=200, headers_dict={"Allow": "GET,PUT,DELETE"}), "leak": None},
            {"response": response("", status=200), "leak": None},
        ]):
            result = files.check_http_methods(BASE)
        self.assertNotEqual(result["risk"], "high")
        self.assertIn("not verified", str(result["evidence"]))


if __name__ == "__main__":
    unittest.main()
