import { useState } from "react";

import { exportPublicKey, getKeyAlgorithmInfo } from "./keyManager";
import { signPrompt } from "./signPrompt";
import "./styles.css";

const initialPrompt = "Send an email to bob@example.com with the project update.";

export default function App() {
  const [prompt, setPrompt] = useState(initialPrompt);
  const [userId, setUserId] = useState("u123");
  const [sessionId, setSessionId] = useState("session-001");
  const [signedEnvelope, setSignedEnvelope] = useState(null);
  const [publicKey, setPublicKey] = useState(null);
  const [algorithmInfo, setAlgorithmInfo] = useState(null);
  const [error, setError] = useState("");
  const [isSigning, setIsSigning] = useState(false);

  async function handleSign() {
    setError("");
    setIsSigning(true);
    try {
      const envelope = await signPrompt(prompt, userId, sessionId);
      const [jwk, keyInfo] = await Promise.all([exportPublicKey(), getKeyAlgorithmInfo()]);
      setSignedEnvelope(envelope);
      setPublicKey(jwk);
      setAlgorithmInfo(keyInfo);
    } catch (signingError) {
      setError(signingError instanceof Error ? signingError.message : "Signing failed.");
    } finally {
      setIsSigning(false);
    }
  }

  return (
    <main>
      <section className="card">
        <p className="eyebrow">Agent-of-Record · Stage 3</p>
        <h1>Client-side signing</h1>
        <p className="intro">
          This page creates a session-only signing key, canonicalizes your prompt with JCS,
          hashes it with SHA3-256, and signs that hash locally. Nothing is sent to a server.
        </p>

        <label htmlFor="user-id">User ID</label>
        <input id="user-id" value={userId} onChange={(event) => setUserId(event.target.value)} />

        <label htmlFor="session-id">Session ID</label>
        <input
          id="session-id"
          value={sessionId}
          onChange={(event) => setSessionId(event.target.value)}
        />

        <label htmlFor="prompt">Prompt</label>
        <textarea
          id="prompt"
          rows="7"
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
        />

        <button type="button" onClick={handleSign} disabled={isSigning}>
          {isSigning ? "Signing…" : "Sign & Submit"}
        </button>
        {error && <p className="error" role="alert">{error}</p>}
      </section>

      {signedEnvelope && (
        <section className="card results" aria-live="polite">
          <h2>Signed envelope</h2>
          <pre>{JSON.stringify(signedEnvelope, null, 2)}</pre>

          <h2>Signing diagnostics</h2>
          <dl>
            <dt>Canonical payload bytes (hex)</dt>
            <dd>{signedEnvelope.canonical_payload_hex}</dd>
            <dt>SHA3-256 payload hash (hex)</dt>
            <dd>{signedEnvelope.hash_sha3_256}</dd>
            <dt>Signature (base64)</dt>
            <dd>{signedEnvelope.signature}</dd>
            <dt>Signature algorithm</dt>
            <dd>{signedEnvelope.signature_algorithm}</dd>
          </dl>

          <h2>Public-key registration material</h2>
          <p className="hint">The private CryptoKey remains in memory and is not displayed or persisted.</p>
          <pre>{JSON.stringify({ pubkey_id: signedEnvelope.pubkey_id, public_jwk: publicKey, algorithm: algorithmInfo }, null, 2)}</pre>
        </section>
      )}
    </main>
  );
}
