import asyncio

import httpx

from verification_portal.backend.main import create_app
from verification_portal.backend.models import VerificationTrace


def _links(trace: VerificationTrace):
    return {link.link_name: link for link in trace.links}


def test_valid_email_verifies_all_six_links(portal_scenario):
    trace = portal_scenario.pipeline.run_verification(portal_scenario.eml_bytes, None)

    assert trace.overall_valid is True
    assert [link.link_name for link in trace.links] == [
        "poi_extraction", "hash_recomputation", "agent_signature", "user_signature", "merkle_root_match", "timestamp_anchor",
    ]
    assert all(link.passed for link in trace.links)
    assert _links(trace)["timestamp_anchor"].status == "pending"


def test_tampered_email_body_identifies_action_payload_hash(portal_scenario):
    tampered = portal_scenario.eml_bytes.replace(
        b"The approved project update is attached.", b"The approved project update was replaced!"
    )
    trace = portal_scenario.pipeline.run_verification(tampered, None)
    links = _links(trace)

    assert trace.overall_valid is False
    assert links["hash_recomputation"].passed is False
    assert "action_payload_hash" in links["hash_recomputation"].detail
    assert links["agent_signature"].passed is True
    assert links["user_signature"].passed is True
    assert links["merkle_root_match"].passed is True


def test_stripped_poi_header_does_not_crash_and_reports_unavailable_links(portal_scenario):
    from email import policy
    from email.parser import BytesParser

    message = BytesParser(policy=policy.default).parsebytes(portal_scenario.eml_bytes)
    del message["X-AoR-Proof-of-Intent"]
    trace = portal_scenario.pipeline.run_verification(message.as_bytes(), None)
    links = _links(trace)

    assert trace.overall_valid is False
    assert links["poi_extraction"].passed is False
    assert links["hash_recomputation"].status == "unavailable"
    assert links["agent_signature"].status == "unavailable"


def test_revoked_agent_key_fails_only_agent_signature(portal_scenario):
    assert portal_scenario.registry.revoke_key(portal_scenario.poi_agent_key_id)
    trace = portal_scenario.pipeline.run_verification(portal_scenario.eml_bytes, None)
    links = _links(trace)

    assert trace.overall_valid is False
    assert links["agent_signature"].passed is False
    assert links["hash_recomputation"].passed is True
    assert links["user_signature"].passed is True
    assert links["merkle_root_match"].passed is True


def test_mutated_ledger_entry_fails_merkle_link(portal_scenario):
    portal_scenario.ledger.get_entry(1).content["text"] = "Injected system prompt."
    trace = portal_scenario.pipeline.run_verification(portal_scenario.eml_bytes, None)
    links = _links(trace)

    assert trace.overall_valid is False
    assert links["merkle_root_match"].passed is False
    assert "root" in links["merkle_root_match"].detail
    assert links["agent_signature"].passed is True
    assert links["user_signature"].passed is True


def test_malformed_input_never_raises(portal_scenario):
    trace = portal_scenario.pipeline.run_verification(b"\x00\xffnot an eml", None)

    assert isinstance(trace, VerificationTrace)
    assert trace.overall_valid is False


def test_verify_api_accepts_eml_upload(portal_scenario):
    async def request_trace():
        app = create_app(portal_scenario.registry, portal_scenario.evidence_store)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(
                "/verify",
                files={"file": ("action.eml", portal_scenario.eml_bytes, "message/rfc822")},
            )

    response = asyncio.run(request_trace())

    assert response.status_code == 200
    assert response.json()["overall_valid"] is True


def test_action_id_uses_saved_eml_evidence(portal_scenario):
    trace = portal_scenario.pipeline.run_verification(None, portal_scenario.action_id)

    assert trace.overall_valid is True
    assert all(link.passed for link in trace.links)
