from __future__ import annotations

import hashlib
import ssl
from typing import Any
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..core import _make_socks_socket, cfg, classify_network_error, default_backend, enable_auto_insecure_https, x509
from ..findings import finding

def check_https_tls(url: str) -> dict[str, Any]:
    name = "HTTPS/TLS sanity"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    if not host:
        return finding(name, "error", "info", "Invalid host")

    try:
        raw = _make_socks_socket(host, port, cfg.tls_timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(raw, server_hostname=host)

        der = ssock.getpeercert(binary_form=True)
        cipher = ssock.cipher()
        version = ssock.version()
        ssock.close()

        evidence = [
            f"HTTPS/TLS reachable on port {port}",
            f"TLS version: {version or 'n/a'}",
            f"Cipher: {cipher[0] if cipher else 'n/a'}",
        ]
        raw_out = {"tls_version": version, "cipher": cipher}

        if der:
            cert_sha256 = hashlib.sha256(der).hexdigest()
            raw_out["cert_sha256"] = cert_sha256
            evidence.append(f"Certificate SHA256: {cert_sha256}")

            if x509 is not None:
                cert = x509.load_der_x509_certificate(der, default_backend())
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
                not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)

                self_issued = bool(subject and issuer and subject == issuer)
                raw_out.update({
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "self_issued": self_issued,
                })

                now = datetime.now(timezone.utc)
                valid_from = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
                valid_until = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
                raw_out["time_valid"] = valid_from <= now <= valid_until
                evidence += [
                    f"Certificate time validity: {'valid' if raw_out['time_valid'] else 'expired or not yet valid'}",
                    f"Subject: {subject}",
                    f"Issuer: {issuer}",
                    f"Valid: {not_before} -> {not_after}",
                ]

                if self_issued:
                    evidence.append("Certificate is self-issued (self-signature not verified)")
                    if cfg.insecure_https:
                        evidence.append("HTTPS certificate verification is disabled explicitly for target HTTP checks")
                    else:
                        evidence.append("HTTPS verification remains enabled unless a target-specific trust failure is observed")
            else:
                evidence.append("Certificate metadata parser unavailable; install cryptography for subject/issuer/validity")

            status = "warn" if raw_out.get("self_issued") else "ok"
            risk = "low" if raw_out.get("self_issued") else "low"
            return finding(name, status, risk, evidence, raw=raw_out, finding_type="network")

        return finding(
            name,
            "warn",
            "medium",
            f"HTTPS/TLS reachable on port {port} but peer certificate was not returned",
            raw=raw_out,
            finding_type="network",
        )

    except Exception as e:
        info = classify_network_error(e)
        return finding(
            name,
            "info",
            "info",
            f"HTTPS/TLS not reachable on port {port} ({info['kind']}): {info['error']}",
            raw=info,
            finding_type="network",
        )
