from __future__ import annotations

import base64
import hashlib
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests

from onionscout import cli, core
from onionscout.findings import finding


KEY = bytes(range(32))
HOST = base64.b32encode(KEY + hashlib.sha3_256(b".onion checksum" + KEY + b"\x03").digest()[:2] + b"\x03").decode().lower() + ".onion"
BASE = "http://" + HOST


def response(text="", status=200, url=BASE):
    r = requests.Response()
    r.status_code = status
    r._content = text.encode()
    r._content_consumed = True
    r.url = url
    r.encoding = "utf-8"
    return r


class TorModeTests(unittest.TestCase):
    def setUp(self):
        self.saved_cfg = core.cfg
        self.saved_session = core.session
        core.cfg = core.Config(target_host=HOST, target_port=None, retries=0, sleep=0)
        core.session = requests.Session()
        core.rebuild_retry_adapter()

    def tearDown(self):
        core.cfg = self.saved_cfg
        core.session = self.saved_session

    def test_transparent_mode_clears_proxy_and_ignores_environment(self):
        core.configure_tor_proxy("127.0.0.1", 9050)
        core.configure_transparent_tor()
        self.assertEqual(core.cfg.tor_mode, "transparent")
        self.assertEqual(core.session.proxies, {})
        self.assertFalse(core.session.trust_env)
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:8888", "HTTPS_PROXY": "http://127.0.0.1:8888", "ALL_PROXY": "http://127.0.0.1:8888"}, clear=True):
            settings = core.session.merge_environment_settings(BASE, {}, False, True, None)
            self.assertEqual(settings["proxies"], {})
            with patch.object(core, "_request_once", return_value=response()) as fetch:
                self.assertEqual(core.request("GET", BASE).status_code, 200)
                fetch.assert_called_once()

    def test_transparent_socket_uses_system_networking(self):
        core.configure_transparent_tor()
        marker = object()
        with patch.object(core.socket, "create_connection", return_value=marker) as connect:
            self.assertIs(core._make_tor_socket(HOST, 443, 3.0), marker)
        connect.assert_called_once_with((HOST, 443), timeout=3.0)

    def test_socks_socket_still_uses_socks_transport(self):
        core.configure_tor_proxy("127.0.0.1", 9050)
        fake = MagicMock()
        socks_module = SimpleNamespace(SOCKS5=2, socksocket=MagicMock(return_value=fake))
        with patch.object(core, "socks", socks_module):
            out = core._make_tor_socket(HOST, 443, 3.0)
        self.assertIs(out, fake)
        fake.set_proxy.assert_called_once_with(2, "127.0.0.1", 9050, rdns=True)
        fake.connect.assert_called_once_with((HOST, 443))

    def test_cli_transparent_requires_external_tor_verification(self):
        argv = ["onionscout", "-u", BASE, "--tor-mode", "transparent"]
        failed = finding("SOCKS/Tor connectivity check", "warn", "low", "Tor exit verification failed")
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "configure_transparent_tor") as configure, \
             patch.object(cli, "preflight_tor_socks") as preflight, \
             patch.object(cli, "check_tor_proxy", return_value=failed), \
             patch.object(cli, "choose_working_origin") as choose:
            with self.assertRaises(SystemExit) as exc:
                cli.main()
        self.assertEqual(exc.exception.code, 1)
        configure.assert_called_once()
        preflight.assert_not_called()
        choose.assert_not_called()

    def test_cli_transparent_rejects_skip_tor_check(self):
        argv = ["onionscout", "-u", BASE, "--tor-mode", "transparent", "--skip-tor-check"]
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "configure_transparent_tor") as configure, \
             patch.object(cli, "check_tor_proxy") as tor_check, \
             patch.object(cli, "choose_working_origin") as choose:
            with self.assertRaises(SystemExit) as exc:
                cli.main()
        self.assertEqual(exc.exception.code, 2)
        configure.assert_not_called()
        tor_check.assert_not_called()
        choose.assert_not_called()

    def test_cli_socks_mode_keeps_preflight(self):
        argv = ["onionscout", "-u", BASE, "--skip-tor-check"]
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "configure_tor_proxy") as configure, \
             patch.object(cli, "preflight_tor_socks", side_effect=RuntimeError("down")), \
             patch.object(cli, "choose_working_origin") as choose:
            with self.assertRaises(SystemExit) as exc:
                cli.main()
        self.assertEqual(exc.exception.code, 1)
        configure.assert_called_once()
        choose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
