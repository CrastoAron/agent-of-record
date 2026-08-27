import { canonicalizePayload, bytesToHex } from "./canonicalize.js";

// Ed25519 is the AoR production target. However, its Web Crypto browser
// support is not reliable enough across all current browser families for this
// Stage 3 demo. ECDSA P-256 is widely available, so every Stage 3 client uses
// it consistently rather than selecting an algorithm per browser.
const DEMO_KEY_ALGORITHM = Object.freeze({ name: "ECDSA", namedCurve: "P-256" });
const DEMO_SIGNING_ALGORITHM = Object.freeze({
  name: "ECDSA",
  hash: { name: "SHA-256" },
});
const SIGNATURE_ALGORITHM_ID = "ECDSA-P256-SHA256";

let keyPair;
let keyPairPromise;
let publicKeyJwk;
let keyId;
let ed25519Support;

function ensureSubtleCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable. Serve this app in a secure browser context.");
  }
}

/**
 * Probe the current browser without adopting the result for the demo protocol.
 * Stage 4 can use this information when the project moves to Ed25519-only keys.
 */
export async function checkEd25519Support() {
  ensureSubtleCrypto();
  if (!ed25519Support) {
    ed25519Support = globalThis.crypto.subtle
      .generateKey({ name: "Ed25519" }, false, ["sign", "verify"])
      .then(() => true)
      .catch(() => false);
  }
  return ed25519Support;
}

/** Generate a session-only P-256 key pair with a non-extractable private key. */
export async function generateKeypair() {
  ensureSubtleCrypto();
  // Evaluate support early for visibility, while keeping the protocol stable.
  await checkEd25519Support();

  keyPair = await globalThis.crypto.subtle.generateKey(
    DEMO_KEY_ALGORITHM,
    false,
    ["sign", "verify"],
  );
  // Web Crypto keeps the public half extractable even when the private half is
  // non-extractable. The private CryptoKey never leaves this module's memory.
  publicKeyJwk = undefined;
  keyId = undefined;
  return keyPair;
}

async function getOrCreateKeypair() {
  if (keyPair) {
    return keyPair;
  }
  // signHash() and getKeyId() run in parallel in signPrompt(). Share the first
  // generation request so the signature and registered public JWK always
  // belong to one key pair.
  keyPairPromise ??= generateKeypair().finally(() => {
    keyPairPromise = undefined;
  });
  return keyPairPromise;
}

/** Export only the public P-256 key as JWK for later registration with Stage 4. */
export async function exportPublicKey() {
  const currentKeyPair = await getOrCreateKeypair();
  if (!publicKeyJwk) {
    publicKeyJwk = await globalThis.crypto.subtle.exportKey("jwk", currentKeyPair.publicKey);
  }
  return { ...publicKeyJwk };
}

/** Derive a deterministic ID from the RFC 8785 canonical public JWK. */
export async function getKeyId() {
  const publicJwk = await exportPublicKey();
  if (!keyId) {
    const canonicalPublicJwk = canonicalizePayload(publicJwk);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", canonicalPublicJwk);
    keyId = `p256-${bytesToHex(new Uint8Array(digest))}`;
  }
  return keyId;
}

/** Sign a precomputed SHA3-256 payload hash with the in-memory private key. */
export async function signHash(hash) {
  if (!(hash instanceof Uint8Array)) {
    throw new TypeError("hash must be a Uint8Array");
  }
  const currentKeyPair = await getOrCreateKeypair();
  return new Uint8Array(
    await globalThis.crypto.subtle.sign(DEMO_SIGNING_ALGORITHM, currentKeyPair.privateKey, hash),
  );
}

export async function getKeyAlgorithmInfo() {
  return {
    selected: SIGNATURE_ALGORITHM_ID,
    ed25519_available_in_this_browser: await checkEd25519Support(),
  };
}
