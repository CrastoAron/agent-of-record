import React, { useState, useEffect } from "react";
import MerkleTreeView from "./MerkleTreeView";

export default function TechnicalEvidenceSection({
  signedEnvelope,
  publicKey,
  algorithmInfo,
  backendResult,
  artifactResult,
  portalTrace,
  backendOperations = [],
  focusedSection = null,
}) {
  const [isMasterExpanded, setIsMasterExpanded] = useState(false);
  const [openSubsections, setOpenSubsections] = useState({
    envelope: false,
    diagnostics: false,
    pubkey: false,
    verification: false,
    artifact: false,
    merkle: false,
    operations: false,
    rawJson: false,
  });

  const [copiedKey, setCopiedKey] = useState(null);

  // If focusedSection is requested (e.g. from node inspection), auto-expand master and that subsection
  useEffect(() => {
    if (focusedSection) {
      setIsMasterExpanded(true);
      setOpenSubsections((prev) => ({ ...prev, [focusedSection]: true }));
      setTimeout(() => {
        const el = document.getElementById(`subevidence-${focusedSection}`);
        if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 50);
    }
  }, [focusedSection]);

  const toggleSubsection = (key) => {
    setOpenSubsections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleCopy = (text, key) => {
    if (!text) return;
    navigator.clipboard?.writeText(typeof text === "string" ? text : JSON.stringify(text, null, 2));
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Composite raw JSON for examiners
  const compositeJson = {
    signed_envelope: signedEnvelope,
    public_key: {
      pubkey_id: signedEnvelope?.pubkey_id,
      public_jwk: publicKey,
      algorithm: algorithmInfo,
    },
    backend_result: backendResult,
    artifact_result: artifactResult,
    portal_trace: portalTrace,
    operations: backendOperations,
  };

  return (
    <section className="technical-evidence-section" id="technical-evidence">
      {/* Master Collapsible Card */}
      <div className="card technical-master-card">
        <button
          type="button"
          className="technical-master-header"
          onClick={() => setIsMasterExpanded(!isMasterExpanded)}
          aria-expanded={isMasterExpanded}
        >
          <div className="master-header-left">
            <span className="master-toggle-arrow">{isMasterExpanded ? "▾" : "▸"}</span>
            <div className="master-title-group">
              <h3 className="master-title">TECHNICAL EVIDENCE</h3>
              <span className="master-sub">
                Cryptographic proofs, hashes, signatures, and raw verification logs
              </span>
            </div>
          </div>
          <span className="btn btn-ghost btn-sm master-action-pill">
            {isMasterExpanded ? "Collapse" : "Expand"}
          </span>
        </button>

        {/* Master Body (Visible only when expanded) */}
        {isMasterExpanded && (
          <div className="technical-master-body">
            <div className="evidence-accordions-group">
              {/* 1. Signed Envelope */}
              <div className={`subaccordion-item ${openSubsections.envelope ? "open" : ""}`} id="subevidence-envelope">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("envelope")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.envelope ? "▾" : "▸"}</span>
                    Signed Envelope
                  </span>
                  <span className="sub-tag">RFC 8785 (JCS)</span>
                </button>
                {openSubsections.envelope && (
                  <div className="subaccordion-content">
                    {signedEnvelope ? (
                      <>
                        <div className="code-block-header">
                          <span>Canonicalized & Signed Payload</span>
                          <button
                            type="button"
                            className="btn btn-ghost btn-xs"
                            onClick={() => handleCopy(signedEnvelope, "envelope")}
                          >
                            {copiedKey === "envelope" ? "✓ Copied" : "Copy"}
                          </button>
                        </div>
                        <pre className="code-block">{JSON.stringify(signedEnvelope, null, 2)}</pre>
                      </>
                    ) : (
                      <p className="text-muted p-2">No signed envelope generated yet.</p>
                    )}
                  </div>
                )}
              </div>

              {/* 2. Signature Diagnostics */}
              <div className={`subaccordion-item ${openSubsections.diagnostics ? "open" : ""}`} id="subevidence-diagnostics">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("diagnostics")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.diagnostics ? "▾" : "▸"}</span>
                    Signature Diagnostics
                  </span>
                  <span className="sub-tag">SHA3-256</span>
                </button>
                {openSubsections.diagnostics && (
                  <div className="subaccordion-content">
                    {signedEnvelope ? (
                      <dl className="diagnostics-list">
                        <dt>Canonical Payload Bytes (Hex)</dt>
                        <dd><code className="code-font text-wrap">{signedEnvelope.canonical_payload_hex}</code></dd>
                        <dt>SHA3-256 Payload Hash (Hex)</dt>
                        <dd><code className="code-font text-wrap">{signedEnvelope.hash_sha3_256}</code></dd>
                        <dt>Digital Signature (Base64)</dt>
                        <dd><code className="code-font text-wrap">{signedEnvelope.signature}</code></dd>
                        <dt>Signature Algorithm</dt>
                        <dd><code className="code-font">{signedEnvelope.signature_algorithm}</code></dd>
                        <dt>Public Key Identifier</dt>
                        <dd><code className="code-font">{signedEnvelope.pubkey_id}</code></dd>
                      </dl>
                    ) : (
                      <p className="text-muted p-2">Diagnostics available after signing.</p>
                    )}
                  </div>
                )}
              </div>

              {/* 3. Public-Key Registration */}
              <div className={`subaccordion-item ${openSubsections.pubkey ? "open" : ""}`} id="subevidence-pubkey">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("pubkey")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.pubkey ? "▾" : "▸"}</span>
                    Public-Key Information
                  </span>
                  <span className="sub-tag">JWK Material</span>
                </button>
                {openSubsections.pubkey && (
                  <div className="subaccordion-content">
                    <p className="hint">The private CryptoKey remains in memory and is never exported or persisted.</p>
                    {publicKey ? (
                      <>
                        <div className="code-block-header">
                          <span>Public JWK Descriptor</span>
                          <button
                            type="button"
                            className="btn btn-ghost btn-xs"
                            onClick={() => handleCopy({ pubkey_id: signedEnvelope?.pubkey_id, public_jwk: publicKey, algorithm: algorithmInfo }, "pubkey")}
                          >
                            {copiedKey === "pubkey" ? "✓ Copied" : "Copy"}
                          </button>
                        </div>
                        <pre className="code-block">
                          {JSON.stringify({ pubkey_id: signedEnvelope?.pubkey_id, public_jwk: publicKey, algorithm: algorithmInfo }, null, 2)}
                        </pre>
                      </>
                    ) : (
                      <p className="text-muted p-2">No public key registered yet.</p>
                    )}
                  </div>
                )}
              </div>

              {/* 4. Backend Verification Result */}
              <div className={`subaccordion-item ${openSubsections.verification ? "open" : ""}`} id="subevidence-verification">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("verification")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.verification ? "▾" : "▸"}</span>
                    Backend Verification Result
                  </span>
                  <span className="sub-tag">FastAPI Response</span>
                </button>
                {openSubsections.verification && (
                  <div className="subaccordion-content">
                    {backendResult ? (
                      <pre className="code-block">{JSON.stringify(backendResult, null, 2)}</pre>
                    ) : (
                      <p className="text-muted p-2">No verification response yet.</p>
                    )}
                  </div>
                )}
              </div>

              {/* 5. Verification Artifact */}
              <div className={`subaccordion-item ${openSubsections.artifact ? "open" : ""}`} id="subevidence-artifact">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("artifact")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.artifact ? "▾" : "▸"}</span>
                    Verification Artifact
                  </span>
                  <span className="sub-tag">.eml Action</span>
                </button>
                {openSubsections.artifact && (
                  <div className="subaccordion-content">
                    {artifactResult ? (
                      <pre className="code-block">{JSON.stringify(artifactResult, null, 2)}</pre>
                    ) : (
                      <p className="text-muted p-2">Artifact is written upon action execution.</p>
                    )}
                  </div>
                )}
              </div>

              {/* 6. Provenance Record / Merkle Tree */}
              <div className={`subaccordion-item ${openSubsections.merkle ? "open" : ""}`} id="subevidence-merkle">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("merkle")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.merkle ? "▾" : "▸"}</span>
                    Provenance Record & Merkle Tree
                  </span>
                  <span className="sub-tag">Trace Verification</span>
                </button>
                {openSubsections.merkle && (
                  <div className="subaccordion-content">
                    {portalTrace ? (
                      <>
                        {portalTrace.merkle_tree && (
                          <div style={{ marginBottom: "1rem" }}>
                            <MerkleTreeView tree={portalTrace.merkle_tree} />
                          </div>
                        )}
                        <pre className="code-block">{JSON.stringify(portalTrace, null, 2)}</pre>
                      </>
                    ) : (
                      <p className="text-muted p-2">Portal trace will appear after artifact verification.</p>
                    )}
                  </div>
                )}
              </div>

              {/* 7. Backend Operations */}
              <div className={`subaccordion-item ${openSubsections.operations ? "open" : ""}`} id="subevidence-operations">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("operations")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.operations ? "▾" : "▸"}</span>
                    Backend Operations
                  </span>
                  <span className="sub-tag">{backendOperations.length} Logs</span>
                </button>
                {openSubsections.operations && (
                  <div className="subaccordion-content">
                    {backendOperations.length === 0 ? (
                      <p className="text-muted p-2">No operations logged yet.</p>
                    ) : (
                      <ul className="diagnostics-list">
                        {backendOperations.map((item, idx) => (
                          <li key={`${item.operation}-${item.timestamp}-${idx}`}>
                            <strong>{item.operation}</strong> · {item.status} · {item.detail} · <span className="code-font">{item.timestamp}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>

              {/* 8. Raw JSON */}
              <div className={`subaccordion-item ${openSubsections.rawJson ? "open" : ""}`} id="subevidence-rawJson">
                <button
                  type="button"
                  className="subaccordion-trigger"
                  onClick={() => toggleSubsection("rawJson")}
                >
                  <span className="sub-title">
                    <span className="sub-arrow">{openSubsections.rawJson ? "▾" : "▸"}</span>
                    Raw JSON
                  </span>
                  <span className="sub-tag">Full Composite Payload</span>
                </button>
                {openSubsections.rawJson && (
                  <div className="subaccordion-content">
                    <div className="code-block-header">
                      <span>Composite JSON Audit Document</span>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        onClick={() => handleCopy(compositeJson, "rawJson")}
                      >
                        {copiedKey === "rawJson" ? "✓ Copied All" : "Copy"}
                      </button>
                    </div>
                    <pre className="code-block">{JSON.stringify(compositeJson, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
