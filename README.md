# Agent-of-Record

## Stage 1: Core crypto primitives

This repository currently contains the standalone Python cryptographic core used
by later AoR stages. It has no networking, web framework, or LLM dependencies.

- `crypto_core/` — RFC 8785 JSON canonicalization, SHA3-256 hashing, and
  Ed25519 signing utilities.
- `crypto_core/tests/` — pytest acceptance tests for the core.
- `ledger_core/` — in-memory append-only context ledger and SHA3-256 Merkle
  tree/proof utilities (Stage 2).
- `frontend/` — Vite/React client-side signing demo (Stage 3); it has its own
  setup instructions and npm dependencies.
- `verifier_service/` — FastAPI signature-verification boundary (Stage 4),
  which rejects invalid client envelopes before any downstream step.
- `demo.py` — a Context Ledger and Merkle-proof forensic demonstration.

The module uses [rfc8785](https://pypi.org/project/rfc8785/), a dedicated RFC
8785 implementation, rather than custom serialization logic. It uses
`cryptography` for its audited Ed25519 primitives.

## Requirements

- Python 3.10 or newer
- `pip` (normally installed with Python)

## Setup

From the repository root, create and activate a project-local virtual
environment, then install the declared dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate it with:

```powershell
.venv\Scripts\Activate.ps1
```

All dependencies are local to `.venv/`, which is excluded from version
control.

## Run and verify

Run the Stage 1 and Stage 2 acceptance suites:

```bash
python -m pytest
```

Run the end-to-end demonstration:

```bash
python demo.py
```

The demo appends sample context entries, prints their hash chain and Merkle
root, validates an inclusion proof, then simulates a direct content mutation.
It reports the first broken ledger entry and shows that the altered leaf no
longer validates against the original Merkle root.

### Stage 2 Merkle conventions

The Context Ledger is in memory and append-only through its public API. Each
leaf commits the entry's `content` and the previous leaf hash using Stage 1's
JCS-plus-SHA3-256 helper. For an odd-sized Merkle level, the final hash is
duplicated as its own right sibling. Each proof item is 33 bytes: a one-byte
direction marker (`00` for a left sibling, `01` for a right sibling), followed
by the 32-byte sibling hash. This makes a proof independently verifiable while
preserving left/right hash order.

If you prefer not to activate the environment, run commands directly through
it:

```bash
.venv/bin/python -m pytest
.venv/bin/python demo.py
```

## Using the crypto core

```python
from crypto_core import canonicalize, generate_keypair, hash_payload, sign, verify

payload = {"prompt": "send an email", "user_id": "u123"}
canonical_bytes = canonicalize(payload)
payload_hash = hash_payload(payload)

private_key, public_key = generate_keypair()
signature = sign(private_key, payload_hash)

assert verify(public_key, signature, payload_hash)
```

`crypto_core.signing` also provides raw-byte and PEM serialization helpers for
Ed25519 keys. Later AoR stages will define secure key registration and storage.

## Stage 3 frontend

The Stage 3 client is kept in [frontend/](frontend/README.md), separate from
the Python core that a later FastAPI verifier will use. It canonicalizes the
five signed fields with JCS, hashes them with SHA3-256, and signs locally with
a non-extractable browser key. See the frontend README for setup, its browser
algorithm decision, and the JS-to-Python cross-check procedure.

## Stage 4 signature verifier

The standalone FastAPI verifier is in `verifier_service/`. It enforces a
60-second timestamp window, detects nonce reuse, resolves a registered public
key, and verifies a Stage 3 signature before the placeholder downstream
handler is permitted to run. Rejections return only
`verification_failed` to the client while the specific reason is logged.

```bash
.venv/bin/python -m uvicorn verifier_service.main:app --reload
.venv/bin/python -m verifier_service.demo
```

`/register-pubkey` accepts either the Stage 3 public P-256 JWK
(`public_key_jwk`) or a base64-encoded DER SubjectPublicKeyInfo key
(`public_key_b64`). The temporary store has the same `register_pubkey` /
`get_pubkey` boundary that Stage 5's key registry will replace.
