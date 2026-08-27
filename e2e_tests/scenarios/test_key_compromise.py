from cryptography.hazmat.primitives.asymmetric import ec

from e2e_tests.pipeline import FullPipeline


def test_agent_revocation_after_action_is_reported_as_current_trust_failure(full_pipeline: FullPipeline):
    submitted = full_pipeline.submit_envelope(
        full_pipeline.make_envelope("Email Bob the approved update."),
        {"to": "bob@example.com", "subject": "Update", "body": "Approved update."},
    )
    assert submitted.trace and submitted.poi_agent_key_id
    assert full_pipeline.registry.revoke_key(submitted.poi_agent_key_id)

    trace = full_pipeline.portal.run_verification(submitted.eml_bytes)
    agent_link = next(link for link in trace.links if link.link_name == "agent_signature")

    assert trace.overall_valid is False
    assert agent_link.passed is False
    assert "historical action" in agent_link.detail


def test_unknown_user_key_is_rejected_before_ledger_or_poi(full_pipeline: FullPipeline):
    unregistered_key = ec.generate_private_key(ec.SECP256R1())
    envelope = full_pipeline.make_envelope(
        "Email Bob the update.", private_key=unregistered_key, pubkey_id="unknown-user-key"
    )
    rejected = full_pipeline.submit_envelope(
        envelope, {"to": "bob@example.com", "subject": "Update", "body": "Approved update."}
    )

    assert rejected.trace is None
    assert rejected.stage4.reason == "unknown_pubkey"
    assert full_pipeline.ledger.all_entries() == []
