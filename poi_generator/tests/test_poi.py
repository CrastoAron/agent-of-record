from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto_core import hash_payload
from ledger_core import Ledger, build_merkle_tree
from poi_generator import build_poi, sign_poi, verify_poi_signature


def _ledger() -> Ledger:
    ledger = Ledger()
    ledger.append("system_prompt", {"text": "Only send approved email."})
    ledger.append("user_prompt", {"text": "Send Bob an update."})
    return ledger


def test_build_poi_hashes_and_context_root_match_existing_primitives() -> None:
    ledger = _ledger()
    action_payload = {"to": "bob@example.com", "subject": "Update"}

    poi = build_poi("Send Bob an update.", "Only send approved email.", ledger, action_payload, "demo-model")

    assert poi.user_prompt_hash == hash_payload({"prompt": "Send Bob an update."}).hex()
    assert poi.system_prompt_hash == hash_payload({"system_prompt": "Only send approved email."}).hex()
    assert poi.action_payload_hash == hash_payload(action_payload).hex()
    assert poi.context_root == build_merkle_tree(ledger.all_entries()).root().hex()
    assert poi.agent_signature is None


def test_signed_poi_verifies_and_tampering_any_field_fails() -> None:
    private_key = Ed25519PrivateKey.generate()
    poi = build_poi("Send email", "Follow policy", _ledger(), {"to": "bob@example.com"}, "demo-model")
    signed_poi = sign_poi(poi, private_key)

    assert verify_poi_signature(signed_poi, private_key.public_key())
    tampered_poi = signed_poi.model_copy(update={"action_payload_hash": "00" * 32})
    assert not verify_poi_signature(tampered_poi, private_key.public_key())
