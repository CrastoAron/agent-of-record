"""Create a Stage 6-style PoI, attach it to a dry-run SMTP email, and inspect it."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from action_executor import ActionExecutor
from action_executor.poi_encoding import decode_poi_header
from action_executor.smtp_action import SMTPConfig
from ledger_core import Ledger
from poi_generator import build_poi, sign_poi, verify_poi_signature


def main() -> None:
    action_payload = {
        "to": "bob@example.com",
        "subject": "Approved project update",
        "body": "The approved project update is attached.",
    }
    ledger = Ledger()
    ledger.append("system_prompt", {"text": "Only send approved project updates."})
    ledger.append("user_prompt", {"text": "Send Bob the approved project update."})
    agent_private_key = Ed25519PrivateKey.generate()
    poi = sign_poi(
        build_poi(
            "Send Bob the approved project update.",
            "Only send approved project updates.",
            ledger,
            action_payload,
            "demo-model",
        ),
        agent_private_key,
    )
    outbox = Path(".aor_outbox")
    executor = ActionExecutor(SMTPConfig(dry_run=True, output_dir=outbox))
    result = executor.execute_action("email", action_payload, poi)
    if not result.success:
        raise RuntimeError(result.detail)

    eml_file = max(outbox.glob("*.eml"), key=lambda path: path.stat().st_mtime)
    message = BytesParser(policy=policy.default).parsebytes(eml_file.read_bytes())
    print("Dry-run message ID:", result.action_id)
    print("EML file:", eml_file)
    for header in ("X-AoR-Proof-of-Intent", "X-AoR-Signature", "X-AoR-Agent-Cert"):
        print(f"{header}: {message[header]}")
    embedded_poi = decode_poi_header(message["X-AoR-Proof-of-Intent"])
    print("Embedded PoI signature verified:", verify_poi_signature(embedded_poi, agent_private_key.public_key()))


if __name__ == "__main__":
    main()
