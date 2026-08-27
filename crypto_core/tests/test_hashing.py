from crypto_core.hashing import hash_payload, hash_sha3_256


def test_hashing_same_payload_is_deterministic() -> None:
    payload = {"prompt": "send email", "user_id": "u123"}

    assert hash_payload(payload) == hash_payload(payload)
    assert len(hash_payload(payload)) == 32


def test_hash_changes_when_payload_value_changes() -> None:
    original = {"prompt": "send email", "user_id": "u123"}
    modified = {"prompt": "delete email", "user_id": "u123"}

    assert hash_payload(original) != hash_payload(modified)


def test_sha3_helper_returns_expected_digest() -> None:
    assert hash_sha3_256(b"AoR").hex() == (
        "c0904c2a062979a46c3d22e9452be37d37d55e4c9e36005f22fc12b060a7a318"
    )
