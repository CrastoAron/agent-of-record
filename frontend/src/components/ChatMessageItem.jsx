import React, { useState } from "react";
import ExecutionResultBanner from "./ExecutionResultBanner";
import ExecutionTimeline from "./ExecutionTimeline";
import CompactExecutionMetadata from "./CompactExecutionMetadata";
import NodeDetailCard from "./NodeDetailCard";
import TechnicalEvidenceSection from "./TechnicalEvidenceSection";

export default function ChatMessageItem({ message, userName = "User" }) {
  const isUser = message.role === "user";
  const [selectedStepId, setSelectedStepId] = useState(null);
  const [focusedEvidenceKey, setFocusedEvidenceKey] = useState(null);

  if (isUser) {
    return (
      <div className="chat-message-row user-row">
        <div className="chat-avatar user-avatar" title={userName}>
          {userName ? userName[0].toUpperCase() : "U"}
        </div>
        <div className="chat-bubble user-bubble">
          <div className="message-header">
            <span className="sender-name">You</span>
            <span className="message-time">
              {message.timestamp ? new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ""}
            </span>
          </div>
          <div className="message-content user-text">{message.content}</div>
        </div>
      </div>
    );
  }

  // Agent Message with Attached Execution Flow
  const execution = message.execution || {};
  const steps = execution.steps || [];
  const selectedStep = steps.find((s) => s.id === selectedStepId) || null;

  const handleSelectStep = (stepId) => {
    setSelectedStepId(stepId);
  };

  const handleViewTechnicalEvidence = (sectionKey) => {
    setFocusedEvidenceKey(sectionKey);
  };

  return (
    <div className="chat-message-row agent-row">
      <div className="chat-avatar agent-avatar" title="Agent-of-Record">
        🛡️
      </div>

      <div className="chat-bubble agent-bubble">
        <div className="message-header">
          <span className="sender-name">Agent-of-Record</span>
          <span className="message-time">
            {message.timestamp ? new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ""}
          </span>
        </div>

        {/* Intro Message */}
        {message.introText && (
          <div className="message-content agent-intro-text">
            {message.introText}
          </div>
        )}

        {execution.agentDraft && (
          <div className="agent-draft-preview">
            <div className="agent-draft-header">
              <strong>Agent email draft</strong>
              <span className="status-badge pass">validated</span>
            </div>
            <div className="agent-draft-row"><span>To</span><code>{execution.agentDraft.to}</code></div>
            <div className="agent-draft-row"><span>Subject</span><span>{execution.agentDraft.subject}</span></div>
            <div className="agent-draft-body">{execution.agentDraft.body}</div>
          </div>
        )}

        {/* Attached Execution Pipeline Container */}
        {execution && steps.length > 0 && (
          <div className="message-execution-attachment">
            {/* 1. Compact Execution Result */}
            <ExecutionResultBanner
              status={message.status || "idle"}
              totalDurationMs={execution.totalDurationMs}
              actionsCount={execution.actionsCount ?? 1}
              errorMessage={message.errorMessage}
            />

            {/* 2. Agent Execution Timeline */}
            <ExecutionTimeline
              steps={steps}
              selectedStepId={selectedStepId}
              onSelectStep={handleSelectStep}
            />

            {/* 3. Compact Execution Metadata */}
            <CompactExecutionMetadata
              status={message.status || "idle"}
              totalDurationMs={execution.totalDurationMs}
              actionsCount={execution.actionsCount ?? 1}
              evidenceRecordsCount={execution.evidenceRecordsCount ?? 6}
              provenanceValid={execution.provenanceValid}
              executionId={execution.actionId || execution.signedEnvelope?.pubkey_id || null}
            />

            {/* 4. Click-to-Inspect Selected Step Details */}
            {selectedStep && (
              <NodeDetailCard
                step={selectedStep}
                onClose={() => setSelectedStepId(null)}
                onViewTechnicalEvidence={handleViewTechnicalEvidence}
              />
            )}

            {/* 5. Collapsible Technical Evidence */}
            {execution.signedEnvelope && (
              <TechnicalEvidenceSection
                signedEnvelope={execution.signedEnvelope}
                publicKey={execution.publicKey}
                algorithmInfo={execution.algorithmInfo}
                backendResult={execution.backendResult}
                artifactResult={execution.artifactResult}
                portalTrace={execution.portalTrace}
                backendOperations={execution.backendOperations || []}
                focusedSection={focusedEvidenceKey}
              />
            )}
          </div>
        )}

        {/* Conclusion / Outcome Message */}
        {message.completionText && (
          <div className="message-content agent-conclusion-text">
            {message.completionText}
          </div>
        )}

        {message.errorMessage && (
          <div className="message-error-alert" role="alert">
            <span>✕ {message.errorMessage}</span>
          </div>
        )}
      </div>
    </div>
  );
}
