from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import paramiko

from ..core import _make_tor_socket, cfg
from ..findings import finding

_PARAMIKO_LOGGER = logging.getLogger("onionscout.paramiko.ssh")
_PARAMIKO_LOGGER.addHandler(logging.NullHandler())
_PARAMIKO_LOGGER.propagate = False

def check_ssh_fingerprint(url: str, ssh_port: int = 22) -> dict[str, Any]:
    name = "SSH fingerprint"
    host = urlparse(url).hostname or ""
    if not host:
        return finding(name, "error", "info", "Invalid host")
    sock = None
    transport = None
    try:
        sock = _make_tor_socket(host, ssh_port, cfg.ssh_timeout)
        transport = paramiko.Transport(sock)
        transport.set_log_channel("onionscout.paramiko.ssh")
        transport.banner_timeout = cfg.ssh_timeout
        transport.start_client(timeout=cfg.ssh_timeout)
        key = transport.get_remote_server_key()
        fp = key.get_fingerprint()
        hex_fp = ":".join(f"{b:02x}" for b in fp)
        return finding(name, "ok", "low", f"SSH Fingerprint: {hex_fp} ({key.get_name()})", raw={"fingerprint": hex_fp, "key_type": key.get_name(), "port": ssh_port})
    except Exception as e:
        return finding(name, "info", "info", f"SSH not exposed or handshake failed: {e}", raw={"port": ssh_port})
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()
