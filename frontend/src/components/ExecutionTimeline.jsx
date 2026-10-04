import React from "react";

export default function ExecutionTimeline({ steps, selectedStepId, onSelectStep }) {
  return (
    <div className="execution-timeline-container" role="region" aria-label="Agent Execution Timeline">
      <div className="timeline-track">
        {steps.map((step, index) => {
          const isSelected = selectedStepId === step.id;
          const isSuccess = step.status === "success";
          const isRunning = step.status === "running";
          const isFailed = step.status === "failed";
          const isSkipped = step.status === "skipped";
          const isPending = !step.status || step.status === "pending";

          const isLast = index === steps.length - 1;
          const nextStep = !isLast ? steps[index + 1] : null;
          const isNextRunning = nextStep && nextStep.status === "running";
          const isConnectorCompleted = isSuccess && nextStep && (nextStep.status === "success" || nextStep.status === "running");
          const isConnectorFailed = isFailed || (nextStep && nextStep.status === "failed");

          return (
            <React.Fragment key={step.id}>
              {/* Step Node */}
              <div
                role="button"
                tabIndex={0}
                className={`timeline-step-node ${step.status || "pending"} ${isSelected ? "selected" : ""}`}
                onClick={() => onSelectStep(isSelected ? null : step.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onSelectStep(isSelected ? null : step.id);
                  }
                }}
                aria-label={`${step.label}: ${step.status || "pending"}. Click to inspect details.`}
              >
                {/* Node Status Icon */}
                <div className={`step-node-icon ${step.status || "pending"}`}>
                  {isSuccess && <span className="icon-check" aria-hidden="true">✓</span>}
                  {isRunning && <span className="icon-spinner" aria-hidden="true" />}
                  {isFailed && <span className="icon-fail" aria-hidden="true">✕</span>}
                  {isSkipped && <span className="icon-dash" aria-hidden="true">—</span>}
                  {isPending && <span className="icon-pending-dot" aria-hidden="true" />}
                </div>

                {/* Node Text & Status */}
                <div className="step-node-body">
                  <span className="step-node-title">{step.label}</span>
                  <span className="step-node-sub">
                    {isRunning && "Running"}
                    {isSuccess && (step.duration_ms !== null ? `${step.duration_ms}ms` : "✓")}
                    {isFailed && "Error"}
                    {isSkipped && "Skipped"}
                    {isPending && "Pending"}
                  </span>
                </div>
              </div>

              {/* Connecting Line to next step */}
              {!isLast && (
                <div
                  className={`timeline-connector ${
                    isConnectorCompleted ? "completed" : ""
                  } ${isNextRunning ? "running" : ""} ${
                    isConnectorFailed ? "failed" : ""
                  }`}
                  aria-hidden="true"
                >
                  <div className="connector-line">
                    {isNextRunning && <div className="connector-particle" />}
                  </div>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
