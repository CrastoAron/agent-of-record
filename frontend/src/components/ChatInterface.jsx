import React, { useState, useEffect, useRef, useMemo } from "react";
import { useAuth } from "../context/AuthContext";
import { exportPublicKey, getKeyAlgorithmInfo } from "../keyManager.js";
import { signPrompt } from "../signPrompt.js";
import { authService, API_BASE } from "../services/authService.js";
import ConversationsSidebar from "./ConversationsSidebar";
import ChatMessageItem from "./ChatMessageItem";
import ChatPromptComposer from "./ChatPromptComposer";
import VerificationPortal from "./VerificationPortal";

const VERIFIER_API_BASE = import.meta.env.VITE_VERIFIER_API_URL ?? "http://127.0.0.1:8000";

const createInitialSteps = () => [
  { id: "request", label: "Request", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
  { id: "identity", label: "Identity", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
  { id: "signature", label: "Signature", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
  { id: "authorization", label: "Authorization", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
  { id: "action", label: "Action", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
  { id: "result", label: "Result", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
  { id: "provenance", label: "Provenance", status: "pending", duration_ms: null, completed_at: null, metadata: {}, error: null },
];

function generateTitleFromPrompt(prompt) {
  const clean = prompt.trim().replace(/^[^a-zA-Z0-9]+/, "");
  if (!clean) return "Agent Action";
  const words = clean.split(/\s+/);
  return words.slice(0, 5).join(" ") + (words.length > 5 ? "…" : "");
}

export default function ChatInterface({
  workspace = "chat",
  onSelectWorkspace,
  prompts = [],
  loadingHistory = false,
  user: propUser,
  onLogout,
}) {
  const { user: authUser } = useAuth();
  const user = propUser || authUser;
  const userId = user?.id || "u123";
  const userName = user?.name || "User";

  const storageKey = `aor_chat_conversations_${userId}`;
  const [conversations, setConversations] = useState(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {
      // Fallback
    }

    const defaultSessionId = `session_${Date.now()}`;
    return [
      {
        id: defaultSessionId,
        title: "Send project update email",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        messages: [],
      },
    ];
  });

  const [activeConversationId, setActiveConversationId] = useState(
    () => conversations[0]?.id || `session_${Date.now()}`
  );

  const [inputPrompt, setInputPrompt] = useState("");
  const [isExecuting, setIsExecuting] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const scrollContainerRef = useRef(null);
  const messagesEndRef = useRef(null);
  const [userScrolledUp, setUserScrolledUp] = useState(false);
  const userScrolledUpRef = useRef(false);
  const [hasNewMessagesWhileScrolledUp, setHasNewMessagesWhileScrolledUp] = useState(false);

  // Smooth scroll to bottom of the chat message area strictly within container
  const scrollToBottom = (behavior = "smooth") => {
    const el = scrollContainerRef.current;
    if (!el) return;
    el.scrollTo({
      top: el.scrollHeight,
      behavior,
    });
  };

  // Scroll detection to respect user intent when scrolling up
  const handleScroll = () => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const { scrollTop, scrollHeight, clientHeight } = el;
    const distanceFromBottom = scrollHeight - (scrollTop + clientHeight);
    const isUp = distanceFromBottom > 60;
    userScrolledUpRef.current = isUp;
    setUserScrolledUp(isUp);
    if (!isUp) {
      setHasNewMessagesWhileScrolledUp(false);
    }
  };

  const handleJumpToLatest = () => {
    userScrolledUpRef.current = false;
    setUserScrolledUp(false);
    setHasNewMessagesWhileScrolledUp(false);
    scrollToBottom("smooth");
  };

  // Keyboard navigation for scroll area (PageUp, PageDown, Home, End)
  const handleKeyDownScroll = (e) => {
    const el = scrollContainerRef.current;
    if (!el) return;
    if (e.target.tagName === "TEXTAREA" || e.target.tagName === "INPUT") return;

    if (e.key === "PageDown") {
      el.scrollBy({ top: el.clientHeight * 0.8, behavior: "smooth" });
      e.preventDefault();
    } else if (e.key === "PageUp") {
      el.scrollBy({ top: -el.clientHeight * 0.8, behavior: "smooth" });
      e.preventDefault();
    } else if (e.key === "Home") {
      el.scrollTo({ top: 0, behavior: "smooth" });
      e.preventDefault();
    } else if (e.key === "End") {
      el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
      e.preventDefault();
    }
  };

  // Sync to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(conversations));
    } catch {
      // Storage quota or private mode handling
    }
  }, [conversations, storageKey]);

  // Find active conversation
  const activeConversation = useMemo(() => {
    return conversations.find((c) => c.id === activeConversationId) || conversations[0];
  }, [conversations, activeConversationId]);

  // When active conversation changes, reset scroll-up state and scroll to bottom
  useEffect(() => {
    userScrolledUpRef.current = false;
    setUserScrolledUp(false);
    setHasNewMessagesWhileScrolledUp(false);
    scrollToBottom("auto");
  }, [activeConversationId]);

  // Auto-scroll messages to bottom when new messages arrive or execution steps progress
  useEffect(() => {
    if (!userScrolledUpRef.current) {
      requestAnimationFrame(() => {
        scrollToBottom("smooth");
      });
    } else {
      setHasNewMessagesWhileScrolledUp(true);
    }
  }, [activeConversation?.messages, isExecuting]);

  // Start new conversation
  const handleNewConversation = () => {
    const newId = `session_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const newConv = {
      id: newId,
      title: "New Action",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: [],
    };
    setConversations((prev) => [newConv, ...prev]);
    setActiveConversationId(newId);
    setInputPrompt("");
  };

  // Delete conversation
  const handleDeleteConversation = (convId) => {
    setConversations((prev) => {
      const filtered = prev.filter((c) => c.id !== convId);
      if (filtered.length === 0) {
        const freshId = `session_${Date.now()}`;
        return [
          {
            id: freshId,
            title: "New Action",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            messages: [],
          },
        ];
      }
      return filtered;
    });

    if (activeConversationId === convId) {
      const remaining = conversations.filter((c) => c.id !== convId);
      if (remaining.length > 0) {
        setActiveConversationId(remaining[0].id);
      }
    }
  };

  // Update a message in the active conversation
  const updateMessage = (messageId, updates) => {
    setConversations((prev) =>
      prev.map((conv) => {
        if (conv.id !== activeConversationId) return conv;
        return {
          ...conv,
          updatedAt: new Date().toISOString(),
          messages: conv.messages.map((m) =>
            m.id === messageId ? { ...m, ...updates } : m
          ),
        };
      })
    );
  };

  // Update a step inside an agent message execution
  const updateMessageStep = (messageId, stepId, stepUpdates) => {
    setConversations((prev) =>
      prev.map((conv) => {
        if (conv.id !== activeConversationId) return conv;
        return {
          ...conv,
          updatedAt: new Date().toISOString(),
          messages: conv.messages.map((m) => {
            if (m.id !== messageId || !m.execution) return m;
            const updatedSteps = (m.execution.steps || []).map((s) =>
              s.id === stepId ? { ...s, ...stepUpdates } : s
            );
            const totalMs = updatedSteps.reduce(
              (sum, s) => (s.duration_ms ? sum + s.duration_ms : sum),
              0
            );
            return {
              ...m,
              execution: {
                ...m.execution,
                steps: updatedSteps,
                totalDurationMs: totalMs,
              },
            };
          }),
        };
      })
    );
  };

  async function fetchBackendOperations() {
    try {
      const response = await fetch(`${VERIFIER_API_BASE}/api/operations`, {
        headers: authService.getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        return data.operations || [];
      }
    } catch {
      // Ignored non-critical failure
    }
    return [];
  }

  // Real backend execution for a user prompt
  const handleSendMessage = async () => {
    const rawPrompt = inputPrompt.trim();
    if (!rawPrompt || isExecuting) return;

    setInputPrompt("");
    setIsExecuting(true);
    userScrolledUpRef.current = false;
    setUserScrolledUp(false);
    setHasNewMessagesWhileScrolledUp(false);
    setTimeout(() => scrollToBottom("smooth"), 50);

    const convId = activeConversation.id;

    // Check prior conversation context
    const previousMessages = activeConversation.messages || [];
    const priorUserMessages = previousMessages.filter((m) => m.role === "user");
    const hasPriorContext = priorUserMessages.length > 0;
    const lastUserPrompt = hasPriorContext
      ? priorUserMessages[priorUserMessages.length - 1].content
      : null;

    // If active conversation title is "New Action", update it from this initial prompt
    if (activeConversation.title === "New Action" || !activeConversation.messages.length) {
      const newTitle = generateTitleFromPrompt(rawPrompt);
      setConversations((prev) =>
        prev.map((c) => (c.id === convId ? { ...c, title: newTitle } : c))
      );
    }

    // 1. Add User Message
    const userMessageId = `msg_user_${Date.now()}`;
    const userMessage = {
      id: userMessageId,
      role: "user",
      content: rawPrompt,
      timestamp: new Date().toISOString(),
    };

    // 2. Add Agent Message in Running state
    const agentMessageId = `msg_agent_${Date.now() + 1}`;
    const initialSteps = createInitialSteps();
    const agentMessage = {
      id: agentMessageId,
      role: "agent",
      status: "running",
      introText: hasPriorContext
        ? `Using context from earlier in this conversation ("${lastUserPrompt?.slice(0, 30)}…"). Authenticating request…`
        : "Request received. Authenticating cryptographic envelope and executing action…",
      completionText: null,
      errorMessage: null,
      timestamp: new Date().toISOString(),
      execution: {
        steps: initialSteps,
        totalDurationMs: 0,
        actionId: null,
        actionsCount: 1,
        evidenceRecordsCount: 6,
        provenanceValid: false,
        signedEnvelope: null,
        publicKey: null,
        algorithmInfo: null,
        backendResult: null,
        artifactResult: null,
        portalTrace: null,
        backendOperations: [],
        agentDraft: null,
      },
    };

    setConversations((prev) =>
      prev.map((c) =>
        c.id === convId
          ? {
              ...c,
              updatedAt: new Date().toISOString(),
              messages: [...c.messages, userMessage, agentMessage],
            }
          : c
      )
    );

    try {
      // Step 1. REQUEST: Canonicalize and sign locally with WebCrypto
      const t1 = performance.now();
      updateMessageStep(agentMessageId, "request", { status: "running" });

      // Construct prompt to sign: includes conversation context if follow-up
      const promptToSign = hasPriorContext
        ? `[Conversation: ${convId} | Context: ${lastUserPrompt}] ${rawPrompt}`
        : rawPrompt;

      const envelope = await signPrompt(promptToSign, userId, convId);
      const [jwk, keyInfo] = await Promise.all([exportPublicKey(), getKeyAlgorithmInfo()]);
      const d1 = Math.round(performance.now() - t1);

      updateMessage(agentMessageId, {
        execution: {
          ...agentMessage.execution,
          signedEnvelope: envelope,
          publicKey: jwk,
          algorithmInfo: keyInfo,
        },
      });

      updateMessageStep(agentMessageId, "request", {
        status: "success",
        duration_ms: d1,
        completed_at: new Date().toISOString(),
        metadata: { prompt: promptToSign, pubkey_id: envelope.pubkey_id },
      });

      // Step 2. IDENTITY: Register session public key with backend Key Registry
      const t2 = performance.now();
      updateMessageStep(agentMessageId, "identity", { status: "running" });
      const regRes = await fetch(`${VERIFIER_API_BASE}/register-pubkey`, {
        method: "POST",
        headers: authService.getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          pubkey_id: envelope.pubkey_id,
          public_key_jwk: jwk,
        }),
      });
      const regData = await regRes.json().catch(() => ({}));
      const d2 = Math.round(performance.now() - t2);

      if (!regRes.ok) {
        throw new Error(regData.detail || "Identity key registration failed.");
      }

      updateMessageStep(agentMessageId, "identity", {
        status: "success",
        duration_ms: d2,
        completed_at: new Date().toISOString(),
        metadata: { pubkey_id: envelope.pubkey_id },
      });

      // Step 3. SIGNATURE: Verify request envelope
      const t3 = performance.now();
      updateMessageStep(agentMessageId, "signature", { status: "running" });
      const verRes = await fetch(`${VERIFIER_API_BASE}/api/prompt`, {
        method: "POST",
        headers: authService.getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(envelope),
      });
      const verData = await verRes.json().catch(() => ({}));
      const d3 = Math.round(performance.now() - t3);

      if (!verRes.ok) {
        throw new Error(verData.detail || "Signature verification failed.");
      }

      updateMessageStep(agentMessageId, "signature", {
        status: "success",
        duration_ms: d3,
        completed_at: new Date().toISOString(),
      });

      // Step 4, 5, 6. AUTHORIZATION, ACTION, RESULT: Commit ledger, execute action & write artifact
      const t4 = performance.now();
      updateMessageStep(agentMessageId, "authorization", { status: "running" });
      const artRes = await fetch(`${VERIFIER_API_BASE}/api/agent/execute`, {
        method: "POST",
        headers: authService.getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(envelope),
      });
      const artData = await artRes.json().catch(() => ({}));
      const d4Total = Math.round(performance.now() - t4);

      if (!artRes.ok) {
        const detail = artData.detail;
        throw new Error(
          typeof detail === "string"
            ? detail
            : detail?.reason || "Action execution failed."
        );
      }
      if (artData.status === "agent_action_failed") {
        const failedResult = (artData.agent_results || []).find((result) => !result.success);
        throw new Error(
          failedResult?.details?.error || "The selected agent could not execute the action."
        );
      }

      const dAuth = Math.max(1, Math.round(d4Total * 0.35));
      const dAct = Math.max(1, Math.round(d4Total * 0.35));
      const dRes = Math.max(1, d4Total - dAuth - dAct);

      updateMessageStep(agentMessageId, "authorization", {
        status: "success",
        duration_ms: dAuth,
        completed_at: new Date().toISOString(),
      });

      updateMessageStep(agentMessageId, "action", {
        status: "success",
        duration_ms: dAct,
        completed_at: new Date().toISOString(),
      });

      updateMessageStep(agentMessageId, "result", {
        status: "success",
        duration_ms: dRes,
        completed_at: new Date().toISOString(),
        metadata: {
          action_id: artData.action_id,
          eml_path: artData.eml_path,
        },
      });

      // Step 7. PROVENANCE: Forensic verification
      const t7 = performance.now();
      updateMessageStep(agentMessageId, "provenance", { status: "running" });
      const traceRes = await fetch(
        `${VERIFIER_API_BASE}/verify/${encodeURIComponent(artData.action_id)}`,
        { headers: authService.getAuthHeaders() }
      );
      const traceData = await traceRes.json().catch(() => ({}));
      const d7 = Math.round(performance.now() - t7);

      if (!traceRes.ok || !traceData.overall_valid) {
        throw new Error("Provenance verification failed.");
      }

      updateMessageStep(agentMessageId, "provenance", {
        status: "success",
        duration_ms: d7,
        completed_at: new Date().toISOString(),
      });

      const ops = await fetchBackendOperations();

      // Finalize Agent Message with all evidence and completion text
      setConversations((prev) =>
        prev.map((c) => {
          if (c.id !== convId) return c;
          return {
            ...c,
            updatedAt: new Date().toISOString(),
            messages: c.messages.map((m) => {
              if (m.id !== agentMessageId) return m;
              return {
                ...m,
                status: "success",
                completionText: `${artData.agent_draft?.agent_type || "Specialized agent"} completed ${artData.agent_draft?.action_type || "the requested action"}. Action ${artData.action_id} executed successfully. Cryptographic proof and Merkle root verified.`,
                execution: {
                  ...m.execution,
                  actionId: artData.action_id,
                  actionsCount: artData.agent_results?.length || 1,
                  evidenceRecordsCount: (artData.agent_results?.length || 1) * 6,
                  backendResult: { registration: regData, verification: verData },
                  artifactResult: artData,
                  agentDraft: artData.agent_draft || null,
                  portalTrace: traceData,
                  backendOperations: ops,
                  provenanceValid: true,
                },
              };
            }),
          };
        })
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Execution failed.";

      setConversations((prev) =>
        prev.map((c) => {
          if (c.id !== convId) return c;
          return {
            ...c,
            updatedAt: new Date().toISOString(),
            messages: c.messages.map((m) => {
              if (m.id !== agentMessageId) return m;
              let reachedFailure = false;
              const updatedSteps = (m.execution?.steps || []).map((s) => {
                if (s.status === "running") {
                  reachedFailure = true;
                  return { ...s, status: "failed", error: msg };
                }
                if (reachedFailure || s.status === "pending") {
                  return { ...s, status: "skipped" };
                }
                return s;
              });
              return {
                ...m,
                status: "failed",
                errorMessage: msg,
                completionText: "Execution could not complete due to a verification or policy rejection.",
                execution: {
                  ...m.execution,
                  steps: updatedSteps,
                },
              };
            }),
          };
        })
      );
    } finally {
      setIsExecuting(false);
    }
  };

  const formattedDate = user?.createdAt
    ? new Date(user.createdAt).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : "Active";

  return (
    <div className="chat-layout-container">
      {/* 1. Conversations Sidebar (Stationary across all views) */}
      <ConversationsSidebar
        conversations={conversations}
        activeConversationId={activeConversationId}
        onSelectConversation={(id) => {
          setActiveConversationId(id);
          if (onSelectWorkspace) onSelectWorkspace("chat");
        }}
        onNewConversation={() => {
          handleNewConversation();
          if (onSelectWorkspace) onSelectWorkspace("chat");
        }}
        onDeleteConversation={handleDeleteConversation}
        isOpen={sidebarOpen}
        onToggleOpen={() => setSidebarOpen(!sidebarOpen)}
        dashboardTab={workspace}
        onSelectTab={onSelectWorkspace}
        promptsCount={prompts?.length || 0}
      />

      {/* 2. Main Workspace Area */}
      <div className="dashboard-main-area">
        {/* Chat view - kept in DOM so background executions or prompt drafting remain uninterrupted */}
        <section
          className="chat-main-area"
          aria-label="Current Conversation"
          style={{ display: workspace === "chat" ? "flex" : "none" }}
        >
          {/* Top Conversation Header */}
          <div className="chat-thread-header">
            <div className="thread-header-left">
              <button
                type="button"
                className="sidebar-toggle-btn"
                onClick={() => setSidebarOpen(!sidebarOpen)}
                title={sidebarOpen ? "Hide sidebar" : "Show sidebar"}
                aria-label="Toggle sidebar"
              >
                ☰
              </button>
              <div className="thread-title-group">
                <h2 className="thread-title">{activeConversation.title || "Agent Execution"}</h2>
                <span className="thread-session-id">
                  Session: <code>{activeConversation.id}</code>
                </span>
              </div>
            </div>

            <div className="thread-header-right">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={handleNewConversation}
                title="Start a new chat"
              >
                + New Action
              </button>
            </div>
          </div>

          {/* Conversation Messages Stream (Only this scrolls) */}
          <div
            className="chat-messages-scroll-area"
            ref={scrollContainerRef}
            onScroll={handleScroll}
            onKeyDown={handleKeyDownScroll}
            tabIndex={0}
            role="region"
            aria-label="Chat messages stream"
          >
            {(!activeConversation.messages || activeConversation.messages.length === 0) ? (
              <div className="chat-empty-state">
                <div className="empty-state-shield">🛡️</div>
                <h3 className="empty-state-title">Agent-of-Record</h3>
                <p className="empty-state-subtitle text-muted">
                  Every request is signed with client-side WebCrypto (Ed25519), authorized with Agent Proof-of-Intent, and verified with immutable Merkle provenance.
                </p>

                <div className="starter-prompts-grid">
                  <button
                    type="button"
                    className="starter-prompt-card"
                    onClick={() => setInputPrompt("Send an email to bob@example.com with the project update.")}
                  >
                    <span className="starter-icon">✉️</span>
                    <span className="starter-title">Send project email</span>
                    <span className="starter-sub text-muted">Sign & dispatch verified email</span>
                  </button>

                  <button
                    type="button"
                    className="starter-prompt-card"
                    onClick={() => setInputPrompt("Audit previous ledger entries and confirm Merkle consistency.")}
                  >
                    <span className="starter-icon">🔍</span>
                    <span className="starter-title">Audit Ledger Records</span>
                    <span className="starter-sub text-muted">Verify Merkle chain & timestamps</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="chat-messages-list">
                {activeConversation.messages.map((message) => (
                  <ChatMessageItem
                    key={message.id}
                    message={message}
                    userName={userName}
                  />
                ))}
                <div ref={messagesEndRef} className="messages-scroll-anchor" />
              </div>
            )}
          </div>

          {/* 3. Sticky AI-Style Prompt Composer */}
          <div className="chat-composer-sticky-container">
            {userScrolledUp && (
              <div className="jump-to-latest-container">
                <button
                  type="button"
                  className="jump-to-latest-btn"
                  onClick={handleJumpToLatest}
                  aria-label="Jump to latest message"
                >
                  <span className="jump-icon">↓</span>
                  <span>{hasNewMessagesWhileScrolledUp ? "New messages" : "Jump to latest"}</span>
                </button>
              </div>
            )}

            <ChatPromptComposer
              value={inputPrompt}
              onChange={setInputPrompt}
              onSend={handleSendMessage}
              isExecuting={isExecuting}
              placeholder="Ask the Agent-of-Record to perform an action..."
            />
          </div>
        </section>

        {/* Secondary View: Verification Portal */}
        {workspace === "verify" && (
          <div className="dashboard-secondary-scroll-area" tabIndex={0}>
            <div className="dashboard-secondary-content">
              <VerificationPortal />
            </div>
          </div>
        )}

        {/* Secondary View: Ledger History */}
        {workspace === "history" && (
          <div className="dashboard-secondary-scroll-area" tabIndex={0}>
            <div className="dashboard-secondary-content">
              <div className="card prompt-history-card">
                <div className="card-header">
                  <h3>🗂 Signed Evidence Records</h3>
                  <span className="status-badge pass">{prompts.length} Entries</span>
                </div>

                {loadingHistory ? (
                  <div className="loading-screen text-center">
                    <div className="spinner" />
                    <p className="text-muted" style={{ marginTop: "0.75rem" }}>Loading evidence ledger…</p>
                  </div>
                ) : prompts.length === 0 ? (
                  <div className="history-empty-state text-center">
                    <div className="empty-icon">📝</div>
                    <h4>No saved actions yet</h4>
                    <p className="text-muted">
                      Submit a prompt in the <strong>Chat</strong> to generate cryptographic proof and ledger records.
                    </p>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      style={{ marginTop: "1rem" }}
                      onClick={() => onSelectWorkspace && onSelectWorkspace("chat")}
                    >
                      Go to Chat →
                    </button>
                  </div>
                ) : (
                  <div className="prompt-history-list">
                    {prompts.map((record) => (
                      <article className="history-item" key={record.action_id || record.id}>
                        <div className="history-main">
                          <p className="history-prompt-text">{record.prompt}</p>
                          <p className="history-timestamp text-muted">
                            🕒 {new Date(record.created_at).toLocaleString()} · Session: <code>{record.session_id}</code>
                          </p>
                        </div>
                        <div className="history-meta">
                          <code className="action-id-tag">{record.action_id || "pending action"}</code>
                          <span className={`status-badge ${record.verification?.overall_valid ? "pass" : "fail"}`}>
                            {record.verification
                              ? (record.verification.overall_valid ? "✓ Verified" : "⚠️ Invalid")
                              : "Awaiting verification"}
                          </span>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Secondary View: Account */}
        {workspace === "account" && (
          <div className="dashboard-secondary-scroll-area" tabIndex={0}>
            <div className="dashboard-secondary-content">
              <section className="dashboard-overview-grid" aria-label="Profile and Session Details">
                <div className="card dashboard-card">
                  <div className="card-header">
                    <h3>👤 Profile Information</h3>
                    <span className="status-badge pass">Active Session</span>
                  </div>
                  <div className="profile-details-list">
                    <div className="detail-item">
                      <span className="detail-label">Full Name</span>
                      <span className="detail-value">{user?.name || "Member"}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Email Address</span>
                      <span className="detail-value">{user?.email || "user@example.com"}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Account ID</span>
                      <span className="detail-value code-font">{user?.id || "u123"}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Member Since</span>
                      <span className="detail-value">{formattedDate}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">User Role</span>
                      <span className="detail-value role-tag">{user?.role || "Operator"}</span>
                    </div>
                  </div>
                </div>

                <div className="card dashboard-card">
                  <div className="card-header">
                    <h3>🛡️ Security & Session Status</h3>
                  </div>
                  <p className="text-muted mb-3" style={{ fontSize: "0.88rem" }}>
                    Keys are generated in-memory via WebCrypto (Ed25519) and registered with backend Key Registry.
                  </p>
                  <div className="security-status-box">
                    <div className="status-row">
                      <span>Authentication Status:</span>
                      <span className="text-pass">✓ Authenticated</span>
                    </div>
                    <div className="status-row">
                      <span>Token Type:</span>
                      <span className="code-font">Bearer Session</span>
                    </div>
                    <div className="status-row">
                      <span>Client State:</span>
                      <span className="text-pass">Local & Backend Active</span>
                    </div>
                  </div>

                  <div className="card-footer-action" style={{ marginTop: "1.25rem" }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-block"
                      onClick={onLogout}
                    >
                      Log Out of Session
                    </button>
                  </div>
                </div>
              </section>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
