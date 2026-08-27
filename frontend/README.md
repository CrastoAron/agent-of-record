# AoR client signing (Stage 3)

This Vite/React app performs the user-side AoR signing flow entirely in the
browser. There are no backend calls in this stage.

## Setup and run

```bash
cd frontend
npm install
npm run dev
```

Open the localhost URL printed by Vite. Web Crypto requires a secure context;
Vite's localhost development origin satisfies that requirement. For deployed
use, serve the app over HTTPS.

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
