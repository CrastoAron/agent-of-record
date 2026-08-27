from e2e_tests.pipeline import FullPipeline


def test_replayed_envelope_creates_no_second_poi_or_ledger_entries(full_pipeline: FullPipeline):
    envelope = full_pipeline.make_envelope("Email Bob the status.", nonce="replay-once")
    action = {"to": "bob@example.com", "subject": "Status", "body": "All systems nominal."}
    first = full_pipeline.submit_envelope(envelope, action)
    before_replay = len(full_pipeline.ledger.all_entries())
    replay = full_pipeline.submit_envelope(envelope, action)

    assert first.trace and first.stage4.valid
    assert replay.trace is None
    assert replay.stage4.reason == "nonce_reused"
    assert len(full_pipeline.ledger.all_entries()) == before_replay


def test_stale_envelope_creates_no_poi_or_ledger_entries(full_pipeline: FullPipeline):
    before = len(full_pipeline.ledger.all_entries())
    stale = full_pipeline.submit_envelope(
        full_pipeline.stale_envelope("Email Bob the status."),
        {"to": "bob@example.com", "subject": "Status", "body": "All systems nominal."},
    )

    assert stale.trace is None
    assert stale.stage4.reason == "timestamp_stale"
    assert len(full_pipeline.ledger.all_entries()) == before
