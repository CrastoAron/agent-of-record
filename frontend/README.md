# Agent-of-Record Unified Frontend

This Vite/React application combines account login, client-side prompt signing,
artifact generation, prompt history, and the forensic trace verification portal
into a single interface. Authentication and history are backed by the FastAPI
SQLite database; the browser private signing key remains session-memory only.

- **Client-Side Signing**: Generates a session-only Web Crypto key, JCS canonicalizes prompt payloads (RFC 8785), hashes via SHA3-256, and produces signed envelopes.
- **Verification Portal**: Uploads `.eml` artifacts or queries Action IDs to verify end-to-end provenance traces against the backend verification service.

## Setup and run

```bash
cd frontend
npm install
npm run dev
```

Open the localhost URL printed by Vite. Web Crypto requires a secure context;
Vite's localhost development origin satisfies that requirement. For deployed
use, serve the app over HTTPS.

Start the backend in a separate terminal before signing or logging in:

```bash
cd ..
.venv/bin/python run_backend.py
```

The backend stores its SQLite database at `../aor_data.sqlite3`. The demo login
shown on the landing page is `user@example.com` / `password123`.

## Cryptographic protocol

1. The five signed fields are `prompt`, `user_id`, `session_id`, `timestamp`,
   and `nonce`.
2. `canonicalize` serializes exactly those fields under RFC 8785 / JCS.
3. `js-sha3` computes a 32-byte SHA3-256 digest, matching the Python Stage 1
   `crypto_core.hash_payload()` result.
4. The browser signs that digest with an in-memory, non-extractable private
   Web Crypto key.

This demo consistently uses **ECDSA P-256 with SHA-256** for its signature
operation (`ECDSA-P256-SHA256`). Although current browsers increasingly expose
Ed25519 through Web Crypto, support is not sufficiently uniform for a
cross-browser demo. `src/keyManager.js` probes local Ed25519 availability for
visibility, but intentionally selects P-256 for every Stage 3 envelope. The
production target remains Ed25519 once the supported browser baseline is
defined.

The Web Crypto P-256 signature is a fixed-width 64-byte raw `r || s` value,
base64-encoded in `signature`. Stage 4 must look up `pubkey_id`, import the
registered public JWK, recompute the five-field JCS/SHA3-256 hash, and verify
an ECDSA P-256 SHA-256 signature over that 32-byte digest. Python
`cryptography` normally expects DER ECDSA signatures, so Stage 4 will need to
convert this raw `r || s` form to DER before verification.

The private `CryptoKey` is module-memory only. It is never exported or written
to localStorage, sessionStorage, IndexedDB, or a network request. Reloading the
page creates a fresh identity on the next signing action, which is intentional
for this demo but will be replaced by an enrolled key strategy in a later stage.

## Cross-check against Python Stage 1

Generate a browser-compatible signed vector with its exact JCS bytes and
SHA3-256 hash:

```bash
npm run cross-check
```

Copy the printed `signed_payload`, `canonical_payload_hex`, and
`hash_sha3_256`, then run the following from the repository root (replace
`PAYLOAD_JSON` with the printed object on one line):

```bash
.venv/bin/python -c 'import json, sys; from crypto_core import canonicalize, hash_payload; p = json.loads(sys.argv[1]); print(canonicalize(p).hex()); print(hash_payload(p).hex())' 'PAYLOAD_JSON'
```

The first Python value must match `canonical_payload_hex`, and the second must
match `hash_sha3_256` byte-for-byte. The timestamp and nonce are generated at
runtime, so compare the values from the same vector output.
