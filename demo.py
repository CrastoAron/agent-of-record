"""Run the Stage 1 AoR canonicalize -> hash -> sign -> verify pipeline."""

from crypto_core import canonicalize, generate_keypair, hash_sha3_256, sign, verify


def main() -> None:
    payload = {
        "prompt": "send an email to bob@example.com",
        "user_id": "u123",
        "timestamp": "2026-08-27T10:00:00Z",
        "nonce": "abc123",
    }

    canonical_bytes = canonicalize(payload)
    digest = hash_sha3_256(canonical_bytes)
    private_key, public_key = generate_keypair()
    signature = sign(private_key, digest)
    is_valid = verify(public_key, signature, digest)

    print(f"Canonical bytes: {canonical_bytes!r}")
    print(f"SHA3-256 digest: {digest.hex()}")
    print(f"Ed25519 signature: {signature.hex()}")
    print(f"Verification result: {is_valid}")


if __name__ == "__main__":
    main()
