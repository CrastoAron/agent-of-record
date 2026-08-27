import canonicalize from "canonicalize";
import jsSha3 from "js-sha3";

const { sha3_256 } = jsSha3;

const textEncoder = new TextEncoder();

/**
 * Encode a JSON-compatible value according to RFC 8785 (JCS).
 *
 * The `canonicalize` package is used instead of custom serialization so this
 * stays byte-for-byte compatible with the server's `rfc8785` implementation.
 */
export function canonicalizePayload(data) {
  const canonicalJson = canonicalize(data);
  if (typeof canonicalJson !== "string") {
    throw new TypeError("Payload cannot be represented as RFC 8785 canonical JSON");
  }
  return textEncoder.encode(canonicalJson);
}

/** Return a SHA3-256 digest as 32 bytes, matching crypto_core.hash_sha3_256. */
export function hashSha3_256(data) {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError("data must be a Uint8Array");
  }
  return new Uint8Array(sha3_256.arrayBuffer(data));
}

/** Canonicalize a payload and return both its bytes and its SHA3-256 digest. */
export function canonicalizeAndHash(data) {
  const canonicalBytes = canonicalizePayload(data);
  return { canonicalBytes, hash: hashSha3_256(canonicalBytes) };
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
