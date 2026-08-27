from crypto_core.signing import (
    deserialize_private_key_pem,
    deserialize_private_key_raw,
    deserialize_public_key_pem,
    deserialize_public_key_raw,
    generate_keypair,
    serialize_private_key_pem,
    serialize_private_key_raw,
    serialize_public_key_pem,
    serialize_public_key_raw,
    sign,
    verify,
)


def test_signature_verifies_with_matching_public_key() -> None:
    private_key, public_key = generate_keypair()
    data = b"canonical payload hash"

    assert verify(public_key, sign(private_key, data), data)


def test_signature_fails_when_data_changes_by_one_byte() -> None:
    private_key, public_key = generate_keypair()
    signature = sign(private_key, b"payload")

    assert not verify(public_key, signature, b"payloae")


def test_signature_fails_with_wrong_public_key() -> None:
    private_key, _ = generate_keypair()
    _, wrong_public_key = generate_keypair()
    data = b"payload"

    assert not verify(wrong_public_key, sign(private_key, data), data)


def test_raw_and_pem_serialization_round_trip() -> None:
    private_key, public_key = generate_keypair()
    data = b"payload hash"

    raw_private = deserialize_private_key_raw(serialize_private_key_raw(private_key))
    raw_public = deserialize_public_key_raw(serialize_public_key_raw(public_key))
    pem_private = deserialize_private_key_pem(serialize_private_key_pem(private_key))
    pem_public = deserialize_public_key_pem(serialize_public_key_pem(public_key))

    assert verify(raw_public, sign(raw_private, data), data)
    assert verify(pem_public, sign(pem_private, data), data)
