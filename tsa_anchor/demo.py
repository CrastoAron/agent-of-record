"""Live Stage 9 walkthrough against FreeTSA, including the Stage 8 adapter."""

from __future__ import annotations

import base64

from ledger_core import Ledger, build_merkle_tree
from tsa_anchor.anchor_scheduler import AnchorStore, anchor_current_root
from tsa_anchor.config import fetch_pinned_root_certificate, load_tsa_config
from tsa_anchor.tsa_verify import verify_timestamp_token
from verification_portal.backend.tsa_verify import verify_timestamp_token as portal_timestamp_check


def main() -> None:
    ledger = Ledger()
    ledger.append("system_prompt", {"text": "Only send approved email."})
    ledger.append("user_prompt", {"text": "Send Bob an approved update."})
    root = build_merkle_tree(ledger.all_entries()).root()
    print("Ledger root:", root.hex())

    record = anchor_current_root(ledger, store=AnchorStore())
    if record.status != "anchored" or record.token_bytes is None:
        print("Anchoring failed:", record.detail)
        return
    print("Anchored at:", record.gen_time.isoformat() if record.gen_time else "unknown")
    print("Timestamp response (base64):", base64.b64encode(record.token_bytes).decode("ascii"))

    root_ca = fetch_pinned_root_certificate(load_tsa_config())
    verified = verify_timestamp_token(record.token_bytes, root, root_ca)
    print("RFC 3161 verification:", verified.verified, verified.gen_time)
    mismatched = verify_timestamp_token(record.token_bytes, b"\xff" * 32, root_ca)
    print("Different-root verification:", mismatched.verified)
    portal_result = portal_timestamp_check(record.token_bytes, root)
    print("Stage 8 timestamp link:", portal_result.detail)


if __name__ == "__main__":
    main()
