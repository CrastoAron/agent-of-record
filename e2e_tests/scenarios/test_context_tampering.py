from e2e_tests.pipeline import FullPipeline


def test_post_action_context_mutation_is_isolated_to_context_integrity(full_pipeline: FullPipeline):
    submitted = full_pipeline.submit_envelope(
        full_pipeline.make_envelope("Email Bob the approved update."),
        {"to": "bob@example.com", "subject": "Update", "body": "Approved update."},
    )
    assert submitted.trace and submitted.trace.overall_valid
    full_pipeline.ledger.get_entry(submitted.context_entry_ids[0]).content["text"] = "Injected replacement system instruction."

    trace = full_pipeline.portal.run_verification(submitted.eml_bytes)
    links = {link.link_name: link for link in trace.links}

    assert trace.overall_valid is False
    assert links["merkle_root_match"].passed is False
    assert links["agent_signature"].passed is True
    assert links["user_signature"].passed is True
