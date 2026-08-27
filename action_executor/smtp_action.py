"""SMTP delivery that attaches signed PoI headers before outbound email leaves AoR."""

from __future__ import annotations

import base64
import json
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path
from uuid import uuid4

from crypto_core import canonicalize
from poi_generator.models import ProofOfIntent

from .cot_encryption import encrypt_cot
from .poi_encoding import build_agent_cert_header, build_signature_header, encode_poi_header


@dataclass(frozen=True)
class SMTPConfig:
    """SMTP connection settings; dry-run output is the default safe behavior."""

    from_address: str = "aor@example.test"
    host: str | None = None
    port: int = 587
    username: str | None = None
    password: str | None = None
    use_starttls: bool = True
    use_ssl: bool = False
    dry_run: bool = True
    output_dir: Path = Path(".aor_outbox")


def _encrypted_reasoning_header(reasoning_text: str, encryption_key: bytes) -> str:
    encrypted = encrypt_cot(reasoning_text, encryption_key)
    # A single base64url JSON value avoids non-ASCII/header-folding ambiguity.
    return base64.urlsafe_b64encode(canonicalize(encrypted)).decode("ascii")


def _build_email(
    to: str,
    subject: str,
    body: str,
    poi: ProofOfIntent,
    smtp_config: SMTPConfig,
    reasoning_text: str | None,
    encryption_key: bytes | None,
) -> EmailMessage:
    message = EmailMessage()
    message["To"] = to
    message["From"] = smtp_config.from_address
    message["Subject"] = subject
    message["Message-ID"] = make_msgid(domain="aor.local")
    message["X-AoR-Proof-of-Intent"] = encode_poi_header(poi)
    message["X-AoR-Signature"] = build_signature_header(poi)
    message["X-AoR-Agent-Cert"] = build_agent_cert_header(poi.agent_pubkey_id)
    if reasoning_text is not None:
        if encryption_key is None:
            raise ValueError("encryption_key is required when adding encrypted reasoning")
        # This is optional encrypted audit rationale, not hidden model CoT.
        message["X-AoR-Encrypted-Reasoning"] = _encrypted_reasoning_header(
            reasoning_text, encryption_key
        )
    message.set_content(body)
    return message


def send_email_with_proof(
    to: str,
    subject: str,
    body: str,
    poi: ProofOfIntent,
    smtp_config: SMTPConfig,
    *,
    reasoning_text: str | None = None,
    encryption_key: bytes | None = None,
) -> str:
    """Attach AoR headers and write/send an email, returning its Message-ID.

    Dry-run writes a standard ``.eml`` file to ``smtp_config.output_dir``. Real
    delivery requires an explicit host and non-dry-run configuration.
    """
    message = _build_email(
        to, subject, body, poi, smtp_config, reasoning_text, encryption_key
    )
    message_id = str(message["Message-ID"])
    if smtp_config.dry_run:
        smtp_config.output_dir.mkdir(parents=True, exist_ok=True)
        (smtp_config.output_dir / f"{uuid4()}.eml").write_bytes(message.as_bytes())
        return message_id

    if not smtp_config.host:
        raise ValueError("host is required for real SMTP delivery")
    client_class = smtplib.SMTP_SSL if smtp_config.use_ssl else smtplib.SMTP
    with client_class(smtp_config.host, smtp_config.port, timeout=20) as client:
        if smtp_config.use_starttls and not smtp_config.use_ssl:
            client.starttls()
        if smtp_config.username:
            client.login(smtp_config.username, smtp_config.password or "")
        client.send_message(message)
    return message_id
