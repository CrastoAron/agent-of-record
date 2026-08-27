import { bytesToBase64, bytesToHex, canonicalizeAndHash } from "./canonicalize.js";
import { getKeyId, signHash } from "./keyManager.js";

/**
 * Create the exact five-field object covered by the user signature.
 * Diagnostic fields appended to the returned envelope are never re-hashed.
 */
export function createSigningPayload(promptText, userId, sessionId) {
  if (!promptText.trim()) {
    throw new Error("A prompt is required before it can be signed.");
  }
  if (!userId.trim() || !sessionId.trim()) {
    throw new Error("Both user ID and session ID are required.");
  }

  return {
    prompt: promptText,
    user_id: userId,
    session_id: sessionId,
    timestamp: new Date().toISOString(),
    nonce: globalThis.crypto.randomUUID(),
  };
}

/**
 * Canonicalize -> SHA3-256 -> sign and return a Stage 4-ready signed envelope.
 *
 * ECDSA has SHA-256 as its Web Crypto signing parameter; it signs the supplied
 * SHA3-256 AoR payload digest. Stage 4 must therefore verify this exact
 * ECDSA-P256-SHA256 signature over the 32-byte `hash_sha3_256` value.
 */
export async function signPrompt(promptText, userId, sessionId) {
  const payload = createSigningPayload(promptText, userId, sessionId);
  const { canonicalBytes, hash } = canonicalizeAndHash(payload);
  const [signature, pubkeyId] = await Promise.all([signHash(hash), getKeyId()]);

  return {
    ...payload,
    signature: bytesToBase64(signature),
    pubkey_id: pubkeyId,
    signature_algorithm: "ECDSA-P256-SHA256",
    // Diagnostics for local development only. Stage 4 recomputes these values
    // from the five signed payload fields, rather than trusting this display.
    canonical_payload_hex: bytesToHex(canonicalBytes),
    hash_sha3_256: bytesToHex(hash),
  };
}
