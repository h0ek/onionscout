from __future__ import annotations

import base64
import hashlib
import sys
import unittest
from unittest.mock import patch

from onionscout import cli, core
from onionscout.findings import finding


KEY = bytes(range(32))
HOST = base64.b32encode(KEY + hashlib.sha3_256(b".onion checksum" + KEY + b"\x03").digest()[:2] + b"\x03").decode().lower() + ".onion"
BASE = "http://" + HOST


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)[:size]


class TorPreflightTests(unittest.TestCase):
    def setUp(self):
        self.cfg_state = dict(core.cfg.__dict__)

    def tearDown(self):
        for key in list(core.cfg.__dict__):
            if key not in self.cfg_state:
                delattr(core.cfg, key)
        for key, value in self.cfg_state.items():
            setattr(core.cfg, key, value)

    def test_socks5_preflight_success(self):
        fake = FakeSocket([b"\x05", b"\x00"])
        with patch.object(core.socket, "create_connection", return_value=fake) as connect:
            core.preflight_tor_socks("127.0.0.1", 9050, 2.0)
        connect.assert_called_once_with(("127.0.0.1", 9050), timeout=2.0)
        self.assertEqual(fake.sent, [b"\x05\x01\x00"])

    def test_socks5_preflight_connection_refused(self):
        with patch.object(core.socket, "create_connection", side_effect=ConnectionRefusedError("refused")):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                core.preflight_tor_socks("127.0.0.1", 9050)

    def test_socks5_preflight_rejects_non_socks5(self):
        fake = FakeSocket([b"\x04\x00"])
        with patch.object(core.socket, "create_connection", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "does not speak SOCKS5"):
                core.preflight_tor_socks("127.0.0.1", 9050)

    def test_cli_aborts_before_origin_when_local_preflight_fails(self):
        argv = ["onionscout", "-u", BASE, "--skip-tor-check"]
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "preflight_tor_socks", side_effect=RuntimeError("proxy down")), \
             patch.object(cli, "check_tor_proxy") as tor_check, \
             patch.object(cli, "choose_working_origin") as choose:
            with self.assertRaises(SystemExit) as exc:
                cli.main()
        self.assertEqual(exc.exception.code, 1)
        tor_check.assert_not_called()
        choose.assert_not_called()

    def test_cli_aborts_before_origin_when_external_tor_verification_fails(self):
        argv = ["onionscout", "-u", BASE]
        failed = finding("SOCKS/Tor connectivity check", "warn", "low", "Tor exit verification failed")
        with patch.object(sys, "argv", argv), \
             patch.object(cli, "preflight_tor_socks", return_value=None), \
             patch.object(cli, "check_tor_proxy", return_value=failed), \
             patch.object(cli, "choose_working_origin") as choose:
            with self.assertRaises(SystemExit) as exc:
                cli.main()
        self.assertEqual(exc.exception.code, 1)
        choose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
