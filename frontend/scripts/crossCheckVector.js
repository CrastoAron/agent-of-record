import { signPrompt } from "../src/signPrompt.js";
import { canonicalizeAndHash } from "../src/canonicalize.js";
import { exportPublicKey } from "../src/keyManager.js";

const envelope = await signPrompt(
  "send an email to bob@example.com",
  "u123",
  "stage3-cross-check",
);

const signedPayload = {
  prompt: envelope.prompt,
  user_id: envelope.user_id,
  session_id: envelope.session_id,
  timestamp: envelope.timestamp,
  nonce: envelope.nonce,
};

const { hash } = canonicalizeAndHash(signedPayload);
const publicKey = await globalThis.crypto.subtle.importKey(
  "jwk",
  await exportPublicKey(),
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["verify"],
);
const signature = Uint8Array.from(Buffer.from(envelope.signature, "base64"));
const signatureValid = await globalThis.crypto.subtle.verify(
  { name: "ECDSA", hash: { name: "SHA-256" } },
  publicKey,
  signature,
  hash,
);
if (!signatureValid) {
  throw new Error("Self-check failed: the signed envelope does not match its public JWK.");
}

console.log(JSON.stringify({
  signed_payload: signedPayload,
  canonical_payload_hex: envelope.canonical_payload_hex,
  hash_sha3_256: envelope.hash_sha3_256,
  signature_self_check: signatureValid,
  signed_envelope: envelope,
}, null, 2));
