import React from "react";
import ExecutionTimeline from "./ExecutionTimeline";

/**
 * Clean adapter for ExecutionMap to maintain backward compatibility with any
 * callers expecting the ExecutionMap component name.
 */
export default function ExecutionMap({ nodes = [], selectedNodeId, onSelectNode }) {
  // Normalize incoming node IDs to the 7 canonical timeline steps
  const idMap = {
    user_request: "request",
    key_registration: "identity",
    signature_verification: "signature",
    policy_context: "authorization",
    action_execution: "action",
    result_captured: "result",
    provenance_recorded: "provenance",
  };

  const reverseMap = {
    request: "user_request",
    identity: "key_registration",
    signature: "signature_verification",
    authorization: "policy_context",
    action: "action_execution",
    result: "result_captured",
    provenance: "provenance_recorded",
  };

  const canonicalSteps = [
    { id: "request", label: "Request" },
    { id: "identity", label: "Identity" },
    { id: "signature", label: "Signature" },
    { id: "authorization", label: "Authorization" },
    { id: "action", label: "Action" },
    { id: "result", label: "Result" },
    { id: "provenance", label: "Provenance" },
  ];

  const steps = canonicalSteps.map((canonical) => {
    const rawNode = nodes.find(
      (n) => n.id === canonical.id || idMap[n.id] === canonical.id
    );
    return {
      id: canonical.id,
      label: canonical.label,
      status: rawNode?.status || "pending",
      duration_ms: rawNode?.duration_ms ?? null,
      completed_at: rawNode?.completed_at ?? null,
      metadata: rawNode?.metadata ?? {},
      error: rawNode?.error ?? null,
    };
  });

  const selectedStepId = idMap[selectedNodeId] || selectedNodeId || null;

  const handleSelect = (stepId) => {
    if (!onSelectNode) return;
    const mappedBack = reverseMap[stepId] || stepId;
    onSelectNode(mappedBack);
  };

  return (
    <ExecutionTimeline
      steps={steps}
      selectedStepId={selectedStepId}
      onSelectStep={handleSelect}
    />
  );
}
