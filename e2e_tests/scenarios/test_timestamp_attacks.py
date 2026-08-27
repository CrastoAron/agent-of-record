from e2e_tests.pipeline import FullPipeline
from verification_portal.backend.tsa_verify import TimestampAnchorResult


def test_unanchored_action_is_verified_with_pending_anchor(full_pipeline: FullPipeline):
    submitted = full_pipeline.submit_envelope(
        full_pipeline.make_envelope("Email Bob the approved update."),
        {"to": "bob@example.com", "subject": "Update", "body": "Approved update."},
    )
    assert submitted.trace
    timestamp_link = next(link for link in submitted.trace.links if link.link_name == "timestamp_anchor")

    # Policy: a valid AoR chain is verified before a periodic external anchor
    # exists, but reviewers can see this is not yet externally time-anchored.
    assert submitted.trace.overall_valid is True
    assert timestamp_link.status == "pending"
    assert timestamp_link.passed is True


def test_forged_timestamp_token_is_a_hard_failure(monkeypatch, full_pipeline: FullPipeline):
    submitted = full_pipeline.submit_envelope(
        full_pipeline.make_envelope("Email Bob the approved update."),
        {"to": "bob@example.com", "subject": "Update", "body": "Approved update."},
    )
    assert submitted.action_id and submitted.eml_bytes
    evidence = full_pipeline.evidence_store.get(submitted.action_id)
    assert evidence is not None
    evidence.timestamp_token = b"forged-rfc3161-token"

    monkeypatch.setattr(
        "verification_portal.backend.verify_pipeline.verify_timestamp_token",
        lambda _token, _root: TimestampAnchorResult(False, False, "RFC 3161 verification failed: forged token"),
    )
    trace = full_pipeline.portal.run_verification(submitted.eml_bytes)
    timestamp_link = next(link for link in trace.links if link.link_name == "timestamp_anchor")

    assert trace.overall_valid is False
    assert timestamp_link.status == "failed"
    assert "forged token" in timestamp_link.detail
