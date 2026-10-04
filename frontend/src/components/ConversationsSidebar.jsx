import React from "react";

export default function ConversationsSidebar({
  conversations = [],
  activeConversationId,
  onSelectConversation,
  onNewConversation,
  onDeleteConversation,
  isOpen = true,
  onToggleOpen,
  dashboardTab = "chat",
  onSelectTab,
  promptsCount = 0,
}) {
  // Group conversations by date: Today, Yesterday, Previous
  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const yesterdayStart = todayStart - 86400000;

  const grouped = {
    today: [],
    yesterday: [],
    previous: [],
  };

  conversations.forEach((conv) => {
    const timestamp = new Date(conv.updatedAt || conv.createdAt).getTime();
    if (timestamp >= todayStart) {
      grouped.today.push(conv);
    } else if (timestamp >= yesterdayStart) {
      grouped.yesterday.push(conv);
    } else {
      grouped.previous.push(conv);
    }
  });

  const handleSelectConv = (convId) => {
    if (onSelectTab) onSelectTab("chat");
    onSelectConversation(convId);
  };

  const renderConversationGroup = (title, items) => {
    if (items.length === 0) return null;

    return (
      <div className="sidebar-group" key={title}>
        <div className="sidebar-group-title">{title}</div>
        <div className="sidebar-group-list">
          {items.map((conv) => {
            const isActive = conv.id === activeConversationId && dashboardTab === "chat";
            return (
              <div
                key={conv.id}
                className={`sidebar-conversation-item ${isActive ? "active" : ""}`}
                onClick={() => handleSelectConv(conv.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    handleSelectConv(conv.id);
                  }
                }}
              >
                <div className="conversation-item-info">
                  <span className="conversation-item-title" title={conv.title}>
                    {conv.title || "Untitled Execution"}
                  </span>
                  <span className="conversation-item-meta">
                    {conv.messages?.length || 0} {(conv.messages?.length || 0) === 1 ? "action" : "actions"}
                  </span>
                </div>

                {onDeleteConversation && conversations.length > 1 && (
                  <button
                    type="button"
                    className="conversation-item-del-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      onDeleteConversation(conv.id);
                    }}
                    title="Delete conversation"
                    aria-label="Delete conversation"
                  >
                    ✕
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <aside className={`conversations-sidebar ${isOpen ? "open" : "collapsed"}`} aria-label="Conversations and Dashboard History">
      {/* 1. Dashboard Submenu Section */}
      <div className="sidebar-dashboard-nav">
        <div className="sidebar-section-eyebrow">Dashboard</div>
        <div className="sidebar-nav-items">
          <button
            type="button"
            className={`sidebar-nav-btn ${dashboardTab === "chat" ? "active" : ""}`}
            onClick={() => onSelectTab && onSelectTab("chat")}
          >
            <span className="sidebar-btn-icon">💬</span>
            <span className="sidebar-btn-label">Chat</span>
          </button>
          <button
            type="button"
            className={`sidebar-nav-btn ${dashboardTab === "verify" ? "active" : ""}`}
            onClick={() => onSelectTab && onSelectTab("verify")}
          >
            <span className="sidebar-btn-icon">🔍</span>
            <span className="sidebar-btn-label">Verify Action</span>
          </button>
          <button
            type="button"
            className={`sidebar-nav-btn ${dashboardTab === "history" ? "active" : ""}`}
            onClick={() => onSelectTab && onSelectTab("history")}
          >
            <span className="sidebar-btn-icon">🗂</span>
            <span className="sidebar-btn-label">Ledger History</span>
            {promptsCount > 0 && (
              <span className="sidebar-btn-badge">{promptsCount}</span>
            )}
          </button>
          <button
            type="button"
            className={`sidebar-nav-btn ${dashboardTab === "account" ? "active" : ""}`}
            onClick={() => onSelectTab && onSelectTab("account")}
          >
            <span className="sidebar-btn-icon">👤</span>
            <span className="sidebar-btn-label">Account</span>
          </button>
        </div>
      </div>

      <div className="sidebar-divider" />

      {/* 2. Conversations Header & New Chat Button */}
      <div className="sidebar-conversations-header">
        <div className="sidebar-section-eyebrow">Conversations</div>
        <button
          type="button"
          className="btn-new-chat"
          onClick={() => {
            if (onSelectTab) onSelectTab("chat");
            onNewConversation();
          }}
          title="Start a new cryptographic conversation"
        >
          <span className="plus-icon">+</span>
          <span>New Chat</span>
        </button>
      </div>

      {/* 3. Independent Scroll Area for Conversations */}
      <div className="sidebar-scrollable-area" tabIndex={0}>
        {conversations.length === 0 ? (
          <div className="sidebar-empty">
            <p className="text-muted">No conversations yet.</p>
          </div>
        ) : (
          <>
            {renderConversationGroup("Today", grouped.today)}
            {renderConversationGroup("Yesterday", grouped.yesterday)}
            {renderConversationGroup("Previous", grouped.previous)}
          </>
        )}
      </div>

      {/* 4. Stationary Status Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-user-pill">
          <span className="pill-dot online" />
          <span className="pill-text">Cryptographic Agent Active</span>
        </div>
      </div>
    </aside>
  );
}
