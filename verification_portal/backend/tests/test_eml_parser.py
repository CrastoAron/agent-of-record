from action_executor import SMTPConfig, send_email_with_proof
from action_executor.tests.conftest import email_payload, signed_email_poi

from verification_portal.backend.eml_parser import parse_eml


def test_parse_eml_extracts_aor_headers_and_original_action_payload(tmp_path):
    poi, _ = signed_email_poi()
    payload = email_payload()
    message_id = send_email_with_proof(**payload, poi=poi, smtp_config=SMTPConfig(output_dir=tmp_path))
    artifact = next(tmp_path.glob("*.eml")).read_bytes()

    parsed = parse_eml(artifact)

    assert parsed["action_id"] == message_id
    assert parsed["action_payload"] == payload
    assert parsed["poi_header"]
    assert parsed["signature_header"]
    assert parsed["agent_cert_header"] == poi.agent_pubkey_id
