import { useState } from "react";

import { exportPublicKey, getKeyAlgorithmInfo } from "../keyManager.js";
import { signPrompt } from "../signPrompt.js";

const initialPrompt = "Send an email to bob@example.com with the project update.";
const VERIFIER_API_BASE = import.meta.env.VITE_VERIFIER_API_URL ?? "http://127.0.0.1:8000";
const initialStages = [
  { id: "client-sign", number: "01", title: "Client signs intent", detail: "Canonicalize, hash, and sign the prompt in Web Crypto.", status: "pending" },
  { id: "register-key", number: "02", title: "Register public key", detail: "Send only the browser public key to the backend registry.", status: "pending" },
  { id: "verify-prompt", number: "03", title: "Verify signed envelope", detail: "Check timestamp, nonce, public key, and user signature.", status: "pending" },
  { id: "build-context", number: "04", title: "Build context ledger", detail: "Commit system and user context to the hash-chained ledger.", status: "pending" },
  { id: "create-poi", number: "05", title: "Create Proof of Intent", detail: "Bind prompt, context root, action payload, and agent signature.", status: "pending" },
  { id: "execute-action", number: "06", title: "Execute protected action", detail: "Attach PoI headers and write the dry-run .eml artifact.", status: "pending" },
  { id: "verify-artifact", number: "07", title: "Verify evidence", detail: "Recompute hashes and verify user, agent, and Merkle links.", status: "pending" },
];

export default function ClientSigning() {
  const [prompt, setPrompt] = useState(initialPrompt);
  const [userId, setUserId] = useState("u123");
  const [sessionId, setSessionId] = useState("session-001");
  const [signedEnvelope, setSignedEnvelope] = useState(null);
  const [publicKey, setPublicKey] = useState(null);
  const [algorithmInfo, setAlgorithmInfo] = useState(null);
  const [backendResult, setBackendResult] = useState(null);
  const [artifactResult, setArtifactResult] = useState(null);
  const [backendOperations, setBackendOperations] = useState([]);
  const [stages, setStages] = useState(initialStages);
  const [portalTrace, setPortalTrace] = useState(null);
  const [error, setError] = useState("");
  const [isSigning, setIsSigning] = useState(false);

  async function refreshOperations() {
    const response = await fetch(`${VERIFIER_API_BASE}/api/operations`);
    const operations = await response.json();
    setBackendOperations(operations.operations ?? []);
  }

  function updateStage(id, status, detail) {
    setStages((current) => current.map((stage) => (
      stage.id === id ? { ...stage, status, detail: detail || stage.detail } : stage
    )));
  }

  async function readJson(response) {
    return response.json().catch(() => ({}));
  }

  async function handleSign() {
    setError("");
    setIsSigning(true);
    setStages(initialStages);
    setPortalTrace(null);
    setBackendResult(null);
    setArtifactResult(null);
    try {
      updateStage("client-sign", "running");
      const envelope = await signPrompt(prompt, userId, sessionId);
      const [jwk, keyInfo] = await Promise.all([exportPublicKey(), getKeyAlgorithmInfo()]);
      setSignedEnvelope(envelope);
      setPublicKey(jwk);
      setAlgorithmInfo(keyInfo);
      updateStage("client-sign", "passed", "Browser signature created; private key stayed in memory.");

      updateStage("register-key", "running");
      const registrationResponse = await fetch(`${VERIFIER_API_BASE}/register-pubkey`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pubkey_id: envelope.pubkey_id,
          public_key_jwk: jwk,
        }),
      });
      const registrationData = await readJson(registrationResponse);
      if (!registrationResponse.ok) {
        throw new Error(registrationData.detail || "Backend key registration failed.");
      }
      updateStage("register-key", "passed", `Backend registered ${envelope.pubkey_id}.`);

      updateStage("verify-prompt", "running");
      const verificationResponse = await fetch(`${VERIFIER_API_BASE}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      const verificationData = await readJson(verificationResponse);
      if (!verificationResponse.ok) {
        throw new Error(verificationData.detail || "Backend verification failed.");
      }
      updateStage("verify-prompt", "passed", "Signature, timestamp, and nonce accepted by FastAPI.");

      updateStage("build-context", "running");
      updateStage("create-poi", "running");
      updateStage("execute-action", "running");
      const artifactResponse = await fetch(`${VERIFIER_API_BASE}/api/generate-artifact`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      });
      const artifactData = await readJson(artifactResponse);
      if (!artifactResponse.ok) {
        throw new Error(artifactData.detail || "Artifact generation failed.");
      }
      updateStage("build-context", "passed", "System and user prompt entries committed to the ledger.");
      updateStage("create-poi", "passed", "Agent-signed PoI created with the current context root.");
      updateStage("execute-action", "passed", `Artifact written: ${artifactData.eml_path}.`);

      updateStage("verify-artifact", "running");
      const portalResponse = await fetch(`${VERIFIER_API_BASE}/verify/${encodeURIComponent(artifactData.action_id)}`);
      const portalData = await readJson(portalResponse);
      if (!portalResponse.ok || !portalData.overall_valid) {
        throw new Error("Generated artifact did not pass portal verification.");
      }
      setPortalTrace(portalData);
      updateStage("verify-artifact", "passed", "All available evidence links passed; timestamp remains pending until anchored.");

      await refreshOperations();
      setSignedEnvelope(envelope);
      setPublicKey(jwk);
      setAlgorithmInfo(keyInfo);
      setBackendResult({
        registration: registrationData,
        verification: verificationData,
      });
      setArtifactResult(artifactData);
    } catch (signingError) {
      setStages((current) => current.map((stage) => (
        stage.status === "running" ? { ...stage, status: "failed", detail: signingError instanceof Error ? signingError.message : "Stage failed." } : stage
      )));
      setError(signingError instanceof Error ? signingError.message : "Signing failed.");
    } finally {
      setIsSigning(false);
    }
  }

  return (
    <div className="signing-container">
      <section className="card">
        <p className="eyebrow">Agent-of-Record · Stage 3</p>
        <h1>Client-side Signing</h1>
        <p className="intro">
          Creates a session-only Web Crypto signing key, canonicalizes your prompt with RFC 8785 (JCS),
          hashes it with SHA3-256, and signs that digest locally in the browser.
        </p>

        <div className="form-group">
          <label htmlFor="user-id">User ID</label>
          <input id="user-id" value={userId} onChange={(event) => setUserId(event.target.value)} />
        </div>

        <div className="form-group">
          <label htmlFor="session-id">Session ID</label>
          <input
            id="session-id"
            value={sessionId}
            onChange={(event) => setSessionId(event.target.value)}
          />
        </div>

        <div className="form-group">
          <label htmlFor="prompt">Prompt</label>
          <textarea
            id="prompt"
            rows="6"
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
          />
        </div>

        <button type="button" onClick={handleSign} disabled={isSigning} className="primary-btn">
          {isSigning ? "Signing…" : "Sign & Submit"}
        </button>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </section>

      {(signedEnvelope || isSigning) && (
        <section className="card results" aria-live="polite">
          <div className="stage-header">
            <div>
              <p className="eyebrow">Live backend trace</p>
              <h2>Request lifecycle</h2>
            </div>
            <span className={`stage-summary ${stages.every((stage) => stage.status === "passed") ? "complete" : "in-progress"}`}>
              {stages.filter((stage) => stage.status === "passed").length}/{stages.length} complete
            </span>
          </div>
          <ol className="stage-list">
            {stages.map((stage) => (
              <li className={`stage-item ${stage.status}`} key={stage.id}>
                <span className="stage-marker">{stage.status === "passed" ? "✓" : stage.status === "failed" ? "!" : stage.number}</span>
                <div className="stage-copy">
                  <div className="stage-title-row">
                    <strong>{stage.title}</strong>
                    <span className="stage-status">{stage.status}</span>
                  </div>
                  <span>{stage.detail}</span>
                </div>
              </li>
            ))}
          </ol>

          {signedEnvelope && (
            <>
              <h2>Signed Envelope</h2>
              <pre className="code-block">{JSON.stringify(signedEnvelope, null, 2)}</pre>

              <h2>Signing Diagnostics</h2>
              <dl className="diagnostics-list">
                <dt>Canonical payload bytes (hex)</dt>
                <dd><code>{signedEnvelope.canonical_payload_hex}</code></dd>
                <dt>SHA3-256 payload hash (hex)</dt>
                <dd><code>{signedEnvelope.hash_sha3_256}</code></dd>
                <dt>Signature (base64)</dt>
                <dd><code>{signedEnvelope.signature}</code></dd>
                <dt>Signature algorithm</dt>
                <dd><code>{signedEnvelope.signature_algorithm}</code></dd>
              </dl>

              <h2>Public-Key Registration Material</h2>
              <p className="hint">The private CryptoKey remains in memory and is never exported or persisted.</p>
              <pre className="code-block">
                {JSON.stringify({ pubkey_id: signedEnvelope.pubkey_id, public_jwk: publicKey, algorithm: algorithmInfo }, null, 2)}
              </pre>

              <h2>Backend Verification Result</h2>
              {backendResult && (
                <pre className="code-block">{JSON.stringify(backendResult, null, 2)}</pre>
              )}

              <h2>Generated Verification Artifact</h2>
              {artifactResult && (
                <pre className="code-block">{JSON.stringify(artifactResult, null, 2)}</pre>
              )}

              {portalTrace && (
                <>
                  <h2>Portal Verification Trace</h2>
                  <pre className="code-block">{JSON.stringify(portalTrace, null, 2)}</pre>
                </>
              )}

              <h2>Backend Operations</h2>
              <ul className="diagnostics-list">
                {backendOperations.length === 0 ? (
                  <li>No backend activity yet.</li>
                ) : (
                  backendOperations.map((item) => (
                    <li key={`${item.operation}-${item.timestamp}-${item.pubkey_id ?? "global"}`}>
                      <strong>{item.operation}</strong> · {item.status} · {item.detail} · {item.timestamp}
                    </li>
                  ))
                )}
              </ul>
            </>
          )}
        </section>
      )}
    </div>
  );
}
