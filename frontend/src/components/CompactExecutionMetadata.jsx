import React, { useState } from "react";

export default function CompactExecutionMetadata({
  status = "idle",
  totalDurationMs = null,
  actionsCount = 1,
  evidenceRecordsCount = 6,
  provenanceValid = false,
  executionId = null,
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!executionId) return;
    navigator.clipboard?.writeText(executionId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isSuccess = status === "success";
  const isFailed = status === "failed";
  const isRunning = status === "running";

  const statusLabel = isSuccess
    ? "SUCCESS"
    : isFailed
    ? "FAILED"
    : isRunning
    ? "RUNNING…"
    : "READY";

  const provenanceLabel = provenanceValid
    ? "Provenance ✓"
    : isRunning
    ? "Provenance …"
    : isFailed
    ? "Provenance ✕"
    : "Provenance —";

  return (
    <div className="compact-metadata-container" role="region" aria-label="Execution Metadata">
      {/* 1. One compact metadata row */}
      <div className="compact-metadata-bar">
        <span className={`meta-item meta-status ${statusLabel.toLowerCase().replace(/[^a-z]/g, "")}`}>
          {statusLabel}
        </span>
        <span className="meta-sep" aria-hidden="true">|</span>

        <span className="meta-item meta-duration">
          {totalDurationMs !== null ? `${totalDurationMs} ms` : "— ms"}
        </span>
        <span className="meta-sep" aria-hidden="true">|</span>

        <span className="meta-item meta-actions">
          {actionsCount} {actionsCount === 1 ? "action" : "actions"}
        </span>
        <span className="meta-sep" aria-hidden="true">|</span>

        <span className="meta-item meta-evidence">
          {evidenceRecordsCount} evidence records
        </span>
        <span className="meta-sep" aria-hidden="true">|</span>

        <span className={`meta-item meta-provenance ${provenanceValid ? "text-pass" : ""}`}>
          {provenanceLabel}
        </span>
      </div>

      {/* 2. Secondary line for Execution ID */}
      {executionId && (
        <div className="execution-id-secondary-line">
          <span className="execution-id-label">Execution ID:</span>
          <code className="execution-id-value">{executionId}</code>
          <button
            type="button"
            className="execution-id-copy-btn"
            onClick={handleCopy}
            title="Copy Execution ID to clipboard"
          >
            {copied ? "✓ Copied" : "Copy"}
          </button>
        </div>
      )}
    </div>
  );
}
