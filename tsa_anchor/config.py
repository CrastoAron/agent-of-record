"""Configuration and pinned-certificate loading for the selected public TSA."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography import x509


_DEFAULT_CONFIG = Path(__file__).with_name("config") / "freetsa.json"


@dataclass(frozen=True)
class TSAConfig:
    endpoint: str
    root_ca_url: str
    root_ca_sha256: str
    request_hash_algorithm: str = "SHA256"
    timeout_seconds: float = 20.0


def load_tsa_config(path: Path | None = None) -> TSAConfig:
    """Load endpoint and root-CA pin from configuration, never code constants."""
    raw = json.loads((path or _DEFAULT_CONFIG).read_text(encoding="utf-8"))
    return TSAConfig(
        endpoint=raw["endpoint"],
        root_ca_url=raw["root_ca_url"],
        root_ca_sha256=raw["root_ca_sha256"].lower(),
        request_hash_algorithm=raw.get("request_hash_algorithm", "SHA256"),
        timeout_seconds=float(raw.get("timeout_seconds", 20)),
    )


def fetch_pinned_root_certificate(config: TSAConfig) -> x509.Certificate:
    """Download the configured root CA and require its pinned SHA-256 digest.

    The downloaded root is data, not a trust decision: the expected digest lives
    in source-controlled configuration and must be reviewed on CA rotation.
    """
    response = httpx.get(config.root_ca_url, timeout=config.timeout_seconds, follow_redirects=True)
    response.raise_for_status()
    certificate_bytes = response.content
    actual = hashlib.sha256(certificate_bytes).hexdigest()
    if actual != config.root_ca_sha256:
        raise ValueError("configured TSA root CA SHA-256 pin does not match download")
    try:
        return x509.load_pem_x509_certificate(certificate_bytes)
    except ValueError:
        return x509.load_der_x509_certificate(certificate_bytes)
