from verifier_service.agent_runtime import AgentRuntime, AgentRuntimeError


def test_demo_agent_extracts_recipient_and_returns_valid_email_action():
    action = AgentRuntime().plan_email(
        "Send the release update to alice@example.com."
    )

    assert action.action_type == "email"
    assert action.to == "alice@example.com"
    assert action.subject
    assert action.body.startswith("Send the release update")
    assert action.action_payload() == {
        "to": "alice@example.com",
        "subject": action.subject,
        "body": action.body,
    }


def test_demo_agent_has_a_deterministic_demo_recipient_when_prompt_has_none():
    action = AgentRuntime().plan_email("Send the approved update.")

    assert action.to == "bob@example.com"


def test_demo_agent_rejects_an_empty_prompt():
    try:
        AgentRuntime().plan_email("  ")
    except AgentRuntimeError as exc:
        assert str(exc) == "agent_prompt_empty"
    else:
        raise AssertionError("expected empty prompt failure")
