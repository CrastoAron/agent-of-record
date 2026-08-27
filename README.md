# Agent-of-Record

Agent-of-Record (AoR) is a cryptographic provenance system for autonomous AI
agent actions. It creates a verifiable link between an authenticated user's
prompt, the context supplied to an agent, the agent's intended tool call, and
the external action that was taken.

The current demonstration focuses on email. Before an action is executed, AoR
verifies the user's signed request, records the relevant context in a
tamper-evident ledger, creates a signed Proof of Intent (PoI), and attaches
that proof to the outgoing `.eml` artifact. The Verification Portal can then
recompute the hashes and report exactly which link passes or fails.

## How It Works

```text
User prompt
    -> canonicalize and hash
    -> user signature verification
    -> append context to the ledger
    -> compute Merkle root
    -> create and sign Proof of Intent
    -> execute the email action with AoR headers
    -> verify the resulting artifact in the portal
```

The system uses RFC 8785 JSON Canonicalization (JCS), SHA3-256, Ed25519
signatures for agents, ECDSA P-256 signatures for the browser client, and an
append-only SHA3-256 hash chain with Merkle proofs for context. RFC 3161
timestamp anchoring is supported through the TSA integration.

## Repository Layout

- `crypto_core/` — JCS canonicalization, SHA3-256 hashing, and signing helpers.
- `ledger_core/` — append-only context ledger and Merkle tree/proof utilities.
- `frontend/` — Vite/React client-side signing demonstration.
- `verifier_service/` — FastAPI boundary that rejects invalid or replayed user envelopes.
- `key_registry/` — SQLite-backed public-key registry and JWK Set publication.
- `poi_generator/` — signed Proof of Intent creation and LangChain callbacks.
- `action_executor/` — dry-run or SMTP email execution with AoR proof headers.
- `verification_portal/` — verification API and React forensic-trace interface.
- `tsa_anchor/` — RFC 3161 timestamp request, storage, and verification support.
- `e2e_tests/` — full-pipeline injection, tamper, replay, key, and timestamp tests.
- `demo.py` — standalone ledger and Merkle-proof demonstration.

## Requirements

- Python 3.10 or newer
- `pip`
- Node.js and npm for the React interfaces

## Installation

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

You can also run Python commands without activating the environment by using
`.venv/bin/python`.

## Run the Demonstrations

Run the basic ledger demonstration:

```bash
.venv/bin/python demo.py
```

Run the full offline adversarial demonstration. It creates fresh in-memory
pipeline components and prints a pass/fail table suitable for a presentation:

```bash
.venv/bin/python -m e2e_tests.run_all_scenarios
```

The table covers legitimate actions, prompt injection through a tool result,
context tampering, nonce replay, agent-key revocation, and timestamp attacks.
No network or manual configuration is required.

The SMTP executor defaults to `dry_run=True`. Its demo writes a standard email
artifact to `.aor_outbox/` and includes:

- `X-AoR-Proof-of-Intent`
- `X-AoR-Signature`
- `X-AoR-Agent-Cert`

To send real mail, provide an explicit `SMTPConfig` with `dry_run=False` and a
dedicated test SMTP account. Do not use production credentials in the demo.

## Run the Tests

Run the complete deterministic test suite:

```bash
.venv/bin/python -m pytest
```

Run only the full-pipeline security scenarios:

```bash
.venv/bin/python -m pytest e2e_tests
```

Network-dependent TSA tests are skipped by default. Run them explicitly only
when network access is available:

```bash
.venv/bin/python -m pytest tsa_anchor/tests -m network
```

## Start the Services

### Signed-prompt verifier

```bash
.venv/bin/python -m uvicorn verifier_service.main:app --reload
```

Open the API documentation at <http://127.0.0.1:8000/docs>. Active public keys
are published at <http://127.0.0.1:8000/.well-known/jwks.json>.

### Verification Portal API

```bash
.venv/bin/python -m uvicorn verification_portal.backend.main:app --reload --port 8001
```

The API accepts an `.eml` artifact or an `action_id` and returns a verification
trace containing six links: PoI extraction, hash recomputation, agent
signature, user signature, Merkle-root matching, and timestamp anchoring.

### Verification Portal UI

In another terminal:

```bash
cd verification_portal/frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5174> to upload an `.eml` file or verify an action ID.
The separate client signing demo is documented in
[frontend/README.md](frontend/README.md).

## Security Behavior

- User envelopes must have a valid registered signature, a fresh timestamp,
  and a nonce that has not been used before.
- Invalid envelopes are rejected before ledger writes, PoI generation, or tool
  execution.
- Every context leaf commits its content and the previous leaf hash.
- A changed context entry produces a different Merkle root and is reported by
  the portal without hiding the other link results.
- A tool-result injection remains distinguishable from the original user
  prompt; the ledger can identify and independently prove the specific leaf.
- A key revoked after an action is reported as a current trust failure. This
  does not by itself prove that the historical action was fraudulent; proving
  historical key status requires retaining a signed revocation snapshot.
- An unanchored ledger root is reported as `pending`, while a forged RFC 3161
  token is a hard verification failure.

## Development Notes

The default demos use in-memory ledgers, in-memory evidence, temporary output,
and SQLite key storage for repeatable local runs. Agent private keys are kept
outside source control for the demos. In production, private keys should be
held by an HSM or KMS, and ledger, evidence, anchor, and nonce storage should
be durable.

The project uses `rfc8785` for canonicalization rather than a hand-written JCS
implementation, and `cryptography` for the Ed25519 and ECDSA primitives.
