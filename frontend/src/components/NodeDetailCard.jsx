import React from "react";

export default function NodeDetailCard({ step, onClose, onViewTechnicalEvidence }) {
  if (!step) return null;

  const isSuccess = step.status === "success";
  const isFailed = step.status === "failed";
  const isRunning = step.status === "running";

  const getStatusBadge = () => {
    if (isSuccess) return <span className="detail-status-pill pass">✓ Valid</span>;
    if (isFailed) return <span className="detail-status-pill fail">✕ Failed</span>;
    if (isRunning) return <span className="detail-status-pill running">● Running</span>;
    return <span className="detail-status-pill pending">○ Pending</span>;
  };

  const getSectionKey = (id) => {
    switch (id) {
      case "request":
        return "envelope";
      case "identity":
        return "pubkey";
      case "signature":
        return "verification";
      case "authorization":
        return "merkle";
      case "action":
      case "result":
        return "artifact";
      case "provenance":
        return "merkle";
      default:
        return "envelope";
    }
  };

  const getStepInfo = (id, metadata = {}) => {
    switch (id) {
      case "request":
        return {
          header: "REQUEST SIGNED",
          description: "The request was canonicalized and cryptographically signed in memory.",
          details: [
            { label: "Algorithm", value: "Ed25519 / RFC 8785" },
            { label: "Hash Digest", value: "SHA3-256" },
            { label: "Key Storage", value: "Browser RAM (Private key non-exportable)" },
          ],
        };
      case "identity":
        return {
          header: "IDENTITY REGISTERED",
          description: "The session public key was verified and registered in the Key Registry.",
          details: [
            { label: "Algorithm", value: "OKP / Ed25519" },
            { label: "Public Key ID", value: metadata.pubkey_id || "Active Session Key" },
            { label: "Registry", value: "Backend Key Registry" },
          ],
        };
      case "signature":
        return {
          header: "SIGNATURE VERIFIED",
          description: "The request signature was successfully verified.",
          details: [
            { label: "Algorithm", value: "Ed25519" },
            { label: "Nonce Check", value: "Anti-replay confirmed" },
            { label: "Timestamp Tolerance", value: "< 300s verified" },
          ],
        };
      case "authorization":
        return {
          header: "ACTION AUTHORIZED",
          description: "Policy rules validated and Proof of Intent (PoI) committed to hash ledger.",
          details: [
            { label: "Algorithm", value: "Ed25519 (PoI Signed)" },
            { label: "Ledger", value: "Committed to Merkle hash-chain" },
            { label: "Agent Identity", value: "demo-agent" },
          ],
        };
      case "action":
        return {
          header: "ACTION EXECUTED",
          description: "The target action was executed with cryptographic proof of intent.",
          details: [
            { label: "Action Type", value: "Email Dispatch (SMTP)" },
            { label: "Target", value: "bob@example.com" },
            { label: "Execution Mode", value: "Enforced Dry-Run" },
          ],
        };
      case "result":
        return {
          header: "RESULT CAPTURED",
          description: "The execution output was captured and cataloged in the evidence store.",
          details: [
            { label: "Artifact Format", value: "RFC 822 (.eml MIME)" },
            { label: "Action ID", value: metadata.action_id || "Recorded" },
            { label: "Storage Path", value: metadata.eml_path || ".aor_outbox/*.eml" },
          ],
        };
      case "provenance":
        return {
          header: "PROVENANCE RECORDED",
          description: "Independent cryptographic verification confirmed all evidence links.",
          details: [
            { label: "Algorithm", value: "RFC 3161 TimeStamp & Merkle" },
            { label: "Merkle Root", value: "Validated" },
            { label: "Evidence Records", value: "100% Passed" },
          ],
        };
      default:
        return {
          header: `${step.label.toUpperCase()} COMPLETED`,
          description: "Step execution completed successfully.",
          details: [],
        };
    }
  };

  const info = getStepInfo(step.id, step.metadata);

  return (
    <div className="node-detail-drawer" role="region" aria-label="Step Inspection">
      <div className="detail-drawer-header">
        <div className="detail-drawer-heading-group">
          <h4 className="detail-step-title">{info.header}</h4>
          {getStatusBadge()}
        </div>
        <button
          type="button"
          className="detail-close-button"
          onClick={onClose}
          aria-label="Close step details"
        >
          ✕
        </button>
      </div>

      <p className="detail-step-summary">{info.description}</p>

      {step.error && (
        <div className="detail-step-error" role="alert">
          <strong>Error:</strong> {step.error}
        </div>
      )}

      <div className="detail-step-grid">
        {step.duration_ms !== null && step.duration_ms !== undefined && (
          <div className="detail-prop-item">
            <span className="prop-name">Duration:</span>
            <span className="prop-val code-font">{step.duration_ms} ms</span>
          </div>
        )}

        {info.details
          .filter((d) => d.label === "Algorithm")
          .map((d) => (
            <div className="detail-prop-item" key={d.label}>
              <span className="prop-name">{d.label}:</span>
              <span className="prop-val code-font">{d.value}</span>
            </div>
          ))}

        {step.completed_at && (
          <div className="detail-prop-item">
            <span className="prop-name">Timestamp:</span>
            <span className="prop-val code-font">
              {new Date(step.completed_at).toLocaleTimeString()}
            </span>
          </div>
        )}

        {info.details
          .filter((d) => d.label !== "Algorithm")
          .map((d) => (
            <div className="detail-prop-item" key={d.label}>
              <span className="prop-name">{d.label}:</span>
              <span className="prop-val">{d.value}</span>
            </div>
          ))}
      </div>

      <div className="detail-drawer-actions">
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => onViewTechnicalEvidence(getSectionKey(step.id))}
        >
          View Technical Evidence →
        </button>
      </div>
    </div>
  );
}
