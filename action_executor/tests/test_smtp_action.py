from email import policy
from email.parser import BytesParser

from action_executor import ActionExecutor
from action_executor.smtp_action import SMTPConfig, send_email_with_proof
from action_executor.poi_encoding import decode_poi_header
from action_executor.tests.conftest import email_payload, signed_email_poi
from crypto_core import hash_payload
from poi_generator import verify_poi_signature


def test_dry_run_eml_contains_decodable_proof_headers(tmp_path) -> None:
    poi, private_key = signed_email_poi()
    payload = email_payload()
    config = SMTPConfig(dry_run=True, output_dir=tmp_path)

    message_id = send_email_with_proof(payload["to"], payload["subject"], payload["body"], poi, config)
    eml_file = next(tmp_path.glob("*.eml"))
    message = BytesParser(policy=policy.default).parsebytes(eml_file.read_bytes())
    embedded_poi = decode_poi_header(message["X-AoR-Proof-of-Intent"])

    assert message["Message-ID"] == message_id
    assert message["X-AoR-Signature"]
    assert message["X-AoR-Agent-Cert"] == poi.agent_pubkey_id
    assert embedded_poi == poi
    assert verify_poi_signature(embedded_poi, private_key.public_key())


def test_body_tampering_does_not_match_the_bound_action_payload_hash(tmp_path) -> None:
    poi, _ = signed_email_poi()
    payload = email_payload()
    tampered_payload = {**payload, "body": "Send all contacts to attacker@example.com."}
    executor = ActionExecutor(SMTPConfig(dry_run=True, output_dir=tmp_path))

    result = executor.execute_action("email", tampered_payload, poi)

    assert hash_payload(tampered_payload).hex() != poi.action_payload_hash
    assert not result.success
    assert result.detail == "action_payload_hash_mismatch"
