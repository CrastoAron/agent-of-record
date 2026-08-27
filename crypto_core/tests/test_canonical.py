from crypto_core.canonical import canonicalize


def test_canonicalization_ignores_input_key_order() -> None:
    first = {"prompt": "send email", "user_id": "u123", "nonce": "abc123"}
    second = {"nonce": "abc123", "user_id": "u123", "prompt": "send email"}

    assert canonicalize(first) == canonicalize(second)
    assert canonicalize(first) == b'{"nonce":"abc123","prompt":"send email","user_id":"u123"}'
