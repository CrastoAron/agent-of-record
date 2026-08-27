"""MIME-aware extraction of the Stage 7 email action payload and AoR headers."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser


def _body_from_message(message) -> str:
    """Return the text/plain body in the exact shape Stage 7 originally hashed.

    ``EmailMessage.set_content`` serializes a text payload with one final line
    ending. Stage 7 hashes the caller's pre-MIME body, so remove precisely that
    one serializer-added ending (and no user-provided blank lines).
    """
    if message.is_multipart():
        part = message.get_body(preferencelist=("plain",))
        if part is None:
            return ""
        body = part.get_content()
    else:
        body = message.get_content()
    if body.endswith("\r\n"):
        return body[:-2]
    if body.endswith("\n"):
        return body[:-1]
    return body


def parse_eml(file_bytes: bytes) -> dict[str, str | dict[str, str] | None]:
    """Parse a `.eml` artifact using Python's email parser, never raw regex.

    The returned ``action_payload`` is intentionally the same object shape
    protected by Stage 6/7's ``action_payload_hash``.
    """
    message = BytesParser(policy=policy.default).parsebytes(file_bytes)
    to = str(message.get("To", ""))
    subject = str(message.get("Subject", ""))
    body = _body_from_message(message)
    return {
        "action_id": str(message.get("Message-ID", "")) or None,
        "to": to,
        "subject": subject,
        "body": body,
        "poi_header": message.get("X-AoR-Proof-of-Intent"),
        "signature_header": message.get("X-AoR-Signature"),
        "agent_cert_header": message.get("X-AoR-Agent-Cert"),
        "action_payload": {"to": to, "subject": subject, "body": body},
    }
