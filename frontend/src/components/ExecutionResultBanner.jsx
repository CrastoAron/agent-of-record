import React from "react";

export default function ExecutionResultBanner({
  status = "idle",
  totalDurationMs = null,
  actionsCount = 1,
  errorMessage = null,
}) {
  const isSuccess = status === "success";
  const isFailed = status === "failed";
  const isRunning = status === "running";

  return (
    <div className="compact-result-banner-container" role="region" aria-label="Execution Result">
      {isSuccess && (
        <div className="compact-result-banner pass" role="status">
          <div className="banner-left">
            <span className="banner-icon-badge pass" aria-hidden="true">✓</span>
            <div className="banner-text">
              <span className="banner-main-title">Execution completed</span>
              <span className="banner-sub-pipeline">
                Request authenticated · Action executed · Result captured · Provenance recorded
              </span>
            </div>
          </div>
          <div className="banner-right">
            <span className="banner-stats">
              {totalDurationMs !== null ? `${totalDurationMs} ms` : "—"} · {actionsCount} {actionsCount === 1 ? "action" : "actions"}
            </span>
          </div>
        </div>
      )}

      {isRunning && (
        <div className="compact-result-banner running" role="status">
          <div className="banner-left">
            <span className="banner-spinner-dot" aria-hidden="true" />
            <div className="banner-text">
              <span className="banner-main-title">Execution in progress</span>
              <span className="banner-sub-pipeline">
                Request authenticated · Action executing · Capturing evidence…
              </span>
            </div>
          </div>
          <div className="banner-right">
            <span className="banner-stats running-tag">Running…</span>
          </div>
        </div>
      )}

      {isFailed && (
        <div className="compact-result-banner fail" role="alert">
          <div className="banner-left">
            <span className="banner-icon-badge fail" aria-hidden="true">✕</span>
            <div className="banner-text">
              <span className="banner-main-title">Execution failed</span>
              <span className="banner-sub-pipeline text-fail">
                {errorMessage || "The execution pipeline failed to verify or execute the action."}
              </span>
            </div>
          </div>
          <div className="banner-right">
            <span className="banner-stats fail-tag">Failed</span>
          </div>
        </div>
      )}

      {status === "idle" && (
        <div className="compact-result-banner idle" role="status">
          <div className="banner-left">
            <span className="banner-icon-badge idle" aria-hidden="true">●</span>
            <div className="banner-text">
              <span className="banner-main-title">Ready for execution</span>
              <span className="banner-sub-pipeline">
                Request authenticated · Action executed · Result captured · Provenance recorded
              </span>
            </div>
          </div>
          <div className="banner-right">
            <span className="banner-stats">7 stages configured</span>
          </div>
        </div>
      )}
    </div>
  );
}
