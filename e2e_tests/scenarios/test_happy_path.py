from e2e_tests.pipeline import FullPipeline


def _email(to: str, subject: str, body: str) -> dict[str, str]:
    return {"to": to, "subject": subject, "body": body}


def test_three_legitimate_actions_verify_end_to_end(full_pipeline: FullPipeline):
    cases = [
        ("Email Bob the project update.", "u123", _email("bob@example.com", "Project update", "The project update is ready.")),
        ("Email Ana the meeting notes.", "u456", _email("ana@example.com", "Meeting notes", "The notes are attached.")),
        ("Email Bob the release status.", "u123", _email("bob@example.com", "Release status", "Release is approved.")),
    ]

    traces = [full_pipeline.submit_and_verify(prompt, user, action) for prompt, user, action in cases]

    assert all(trace.overall_valid for trace in traces)
    assert all(all(link.passed for link in trace.links) for trace in traces)
    assert all(next(link for link in trace.links if link.link_name == "timestamp_anchor").status == "pending" for trace in traces)
