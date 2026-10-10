from aor.agents.email import EmailAgent


def test_email_agent_preserves_deterministic_planning_behavior() -> None:
    plan = EmailAgent().plan("Send the release update to alice@example.com.")

    assert plan.agent_type == "email"
    assert plan.agent_id == "email-agent"
    assert plan.action_type == "email"
    assert plan.payload == {
        "to": "alice@example.com",
        "subject": "Approved project update",
        "body": "Send the release update to alice@example.com.",
    }


def test_email_agent_uses_the_existing_demo_recipient_fallback() -> None:
    plan = EmailAgent().plan("Send the approved update.")

    assert plan.payload["to"] == "bob@example.com"
