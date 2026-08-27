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
- `key_registry/` — SQLite-backed agent public-key registry and JWK Set
  publication layer (Stage 5).
- `poi_generator/` — signed Proof of Intent generation and LangChain pre-tool
  callback integration (Stage 6).
- `action_executor/` — SMTP outbound boundary that writes/sends PoI-attached
  email actions (Stage 7).
- `verification_portal/` — FastAPI verification trace API and separate React
  portal UI (Stage 8).
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

Run all implemented-stage acceptance suites:

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

After starting Uvicorn, open the interactive API documentation at
`http://127.0.0.1:8000/docs`. The service intentionally has no browser
homepage at `/`; inspect its published active keys at
`http://127.0.0.1:8000/.well-known/jwks.json` instead.

`/register-pubkey` accepts either the Stage 3 public P-256 JWK
(`public_key_jwk`) or a base64-encoded DER SubjectPublicKeyInfo key
(`public_key_b64`).

## Stage 5 key registry

Stage 5 replaces the default in-memory key lookup with `KeyRegistry`, backed by
SQLite. It maps `agent_id` to public keys with validity windows and revocation
state. `get_pubkey(pubkey_id)` returns `None` for unknown, expired,
not-yet-valid, and revoked keys, so Stage 4 exposes each case as the same
generic verification failure.

### Run Stage 5

```bash
.venv/bin/python -m pytest key_registry/tests
.venv/bin/python -m key_registry.demo
```

The FastAPI endpoints are:

- `POST /register-key` — register an agent public key, its algorithm, and its validity window.
- `POST /revoke-key` — revoke a registered `pubkey_id`.
- `GET /.well-known/jwks.json` — publish only active, non-revoked public keys.

The older `/register-pubkey` route is retained as a Stage 4 compatibility shim.
The registry supports Ed25519 (`OKP`) and the Stage 3 ECDSA P-256 (`EC`) keys.
X.509 certificate issuance is deferred: the `AgentKeyRecord` validity/revocation
model is compatible with a future certificate/KMS-backed implementation, while
JWK Sets cover the demo's public key-distribution needs.

## Stage 6 Proof of Intent generator

Stage 6 creates a signed PoI immediately before each LangChain tool call. It
commits the verified user prompt, active system prompt, current Context Ledger
Merkle root, exact tool payload, model ID, timestamp, and nonce. The callback
requires `metadata={"session_id": ...}` and blocks execution if no verified
session context exists for that ID.

```bash
.venv/bin/python -m pytest poi_generator/tests
.venv/bin/python -m poi_generator.demo
```

The implementation targets `langchain-core` 1.5's
`on_tool_start(serialized, input_str, *, run_id, parent_run_id, tags, metadata,
inputs, **kwargs)` callback shape. Agent Ed25519 keys are demo-persisted in the
ignored `.aor_agent_keys/` directory and registered in Stage 5 on startup. In
production, agent private keys belong in KMS/HSM custody instead.

## Stage 7 action executor

Stage 7 is the required outbound boundary: it checks that the exact action
payload still matches the signed PoI and attaches it before any email is sent.
The SMTP action adds `X-AoR-Proof-of-Intent` (the full canonical base64url
PoI), `X-AoR-Signature` (a redundant quick-check copy), and
`X-AoR-Agent-Cert` (the Stage 5 public-key reference). Optional encrypted audit
rationale is carried in `X-AoR-Encrypted-Reasoning` using AES-256-GCM; it is
for explicitly supplied audit rationale, not private model reasoning.

```bash
.venv/bin/python -m pytest action_executor/tests
.venv/bin/python -m action_executor.demo
```

The demo uses `dry_run=True`, writes a standard `.eml` artifact to the ignored
`.aor_outbox/` directory, prints its AoR headers, decodes the embedded PoI, and
verifies its agent signature. Set `SMTPConfig(dry_run=False, host=..., ...)`
only with a dedicated test SMTP account for a live panel demonstration.

## Stage 8 verification portal

Stage 8 provides the panel-facing forensic trace. It accepts a Stage 7 `.eml`
artifact or an `action_id` and checks the PoI header, all committed hashes,
agent signature, original user signature, live Context Ledger Merkle root, and
timestamp-anchor state. It always returns all six links, even if one fails.

Run its tests and the three-case presentation walkthrough:

```bash
.venv/bin/python -m pytest verification_portal/backend/tests
.venv/bin/python -m verification_portal.demo
```

Run the API on port 8001 (Stage 4 already uses port 8000):

```bash
.venv/bin/python -m uvicorn verification_portal.backend.main:app --reload --port 8001
```

Then run the separate React UI in another terminal:

```bash
cd verification_portal/frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5174`. The portal UI uploads `.eml` files or submits an
action ID to the API. Its default in-memory server has no saved action evidence;
the presentation demo and an application integration must register an
`ActionEvidence` record at action time (the original signed envelope, system
prompt, ledger snapshot boundary, and optional `.eml`) in `ActionEvidenceStore`.
This is deliberately explicit until persistence is introduced in a later stage.
When Stage 9 is enabled, pass the shared `AnchorStore` to the portal app; the
portal looks up the signed context root there before verifying its token.

For a MIME text body written by Stage 7, the parser removes exactly the single
terminal newline added by `EmailMessage.set_content`, so its reconstructed
`{to, subject, body}` matches the pre-MIME payload that the PoI hashes.
Timestamp anchoring is shown as **pending**, not silently accepted: RFC 3161 TSA
token generation and cryptographic validation are Stage 9 work.

## Stage 9 RFC 3161 timestamp anchoring

Stage 9 anchors the current Stage 2 Merkle root — never raw prompt or ledger
content — with an RFC 3161 Time Stamp Authority. It uses the actively maintained
[`rfc3161-client`](https://pypi.org/project/rfc3161-client/) package for TSP
encoding/parsing and CMS signature-chain verification.

The default provider is FreeTSA at `https://freetsa.org/tsr`. Its source-controlled
configuration is [freetsa.json](tsa_anchor/config/freetsa.json): it contains the
endpoint, published CA certificate URL, and a pinned CA SHA-256 digest. The
provider currently publishes its request endpoint, CA certificate, and OpenSSL
verification procedure at [FreeTSA's timestamping guide](https://freetsa.org/index_en.php).
The CA pin must be reviewed and deliberately updated if that provider rotates
its CA.

FreeTSA advertises SHA-256/384/512 message imprints, whereas the AoR ledger root
is SHA3-256. Therefore, the timestamp's standard SHA-256 `hashedMessage` commits
to the exact 32 bytes of the SHA3 ledger root. Verification applies the token's
declared imprint algorithm to the supplied root and compares the result with the
embedded digest, so a timestamp for one root cannot be presented as evidence for
another.

Run normal deterministic tests (network tests are skipped by default):

```bash
.venv/bin/python -m pytest tsa_anchor/tests
```

Run the explicit live-TSA checks and the panel walkthrough:

```bash
.venv/bin/python -m pytest tsa_anchor/tests -m network
.venv/bin/python -m tsa_anchor.demo
```

`AnchorStore` is an in-memory, append-only list keyed by ledger root for this
stage. `AnchorScheduler` checks every five minutes by default and avoids duplicate
requests for an already anchored unchanged root; failed attempts are retained and
may be retried on the next interval. Production should persist these records and
batch roots with a durable scheduler.

The portal's timestamp link now delegates to the Stage 9 verifier. It reports
`verified, anchored at <genTime>` for a valid stored RFC 3161 response and retains
the distinct `pending` state when an action has not yet been anchored.
