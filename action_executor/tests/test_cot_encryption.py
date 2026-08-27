import pytest

from action_executor.cot_encryption import decrypt_cot, encrypt_cot, generate_encryption_key
from cryptography.exceptions import InvalidTag


def test_aes_gcm_reasoning_round_trips_and_wrong_key_fails() -> None:
    key = generate_encryption_key()
    encrypted = encrypt_cot("Approved because the request matches policy.", key)

    assert decrypt_cot(encrypted, key) == "Approved because the request matches policy."
    with pytest.raises(InvalidTag):
        decrypt_cot(encrypted, generate_encryption_key())
