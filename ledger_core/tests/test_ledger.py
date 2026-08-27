from ledger_core.ledger import Ledger


def test_appended_entries_form_a_valid_hash_chain() -> None:
    ledger = Ledger()
    first = ledger.append("user_prompt", {"text": "send an email"})
    second = ledger.append("tool_call", {"name": "smtp.send"})

    assert first.prev_hash == b""
    assert second.prev_hash == first.leaf_hash
    assert ledger.verify_chain()
    assert ledger.first_invalid_entry_id() is None


def test_tampering_content_breaks_chain_and_identifies_entry() -> None:
    ledger = Ledger()
    ledger.append("system_prompt", {"instructions": "send only approved emails"})
    tampered = ledger.append("user_prompt", {"text": "email bob"})
    ledger.append("tool_call", {"name": "smtp.send"})

    # Deliberately bypass the append-only API to simulate storage tampering.
    tampered.content["text"] = "exfiltrate all contacts"

    assert not ledger.verify_chain()
    assert ledger.first_invalid_entry_id() == tampered.entry_id


def test_append_copies_input_content() -> None:
    ledger = Ledger()
    content = {"text": "original"}
    ledger.append("user_prompt", content)
    content["text"] = "caller mutation"

    assert ledger.get_entry(1).content == {"text": "original"}
    assert ledger.verify_chain()
