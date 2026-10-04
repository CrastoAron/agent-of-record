import React, { useRef, useEffect } from "react";

export default function ChatPromptComposer({
  value,
  onChange,
  onSend,
  isExecuting = false,
  placeholder = "Ask the Agent-of-Record to perform an action...",
}) {
  const textareaRef = useRef(null);

  // Automatically grow textarea as user types, up to max-height
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    const newHeight = Math.max(100, Math.min(el.scrollHeight, 260));
    el.style.height = `${newHeight}px`;
  }, [value]);

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!isExecuting && value.trim()) {
        onSend();
      }
    }
  };

  const handlePresetClick = (presetText) => {
    if (isExecuting) return;
    onChange(presetText);
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  };

  return (
    <div className="chat-composer-wrapper">
      <div className={`chat-composer-box ${value.trim() ? "has-text" : ""}`}>
        <textarea
          ref={textareaRef}
          className="chat-composer-textarea"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          disabled={isExecuting}
          rows={3}
          aria-label="Agent Prompt Input"
        />

        <div className="chat-composer-footer">
          <div className="composer-left-tools">
            <span className="composer-crypt-badge" title="Cryptographically signed using WebCrypto Ed25519">
              <span className="badge-dot" />
              <span>Cryptographically Signed</span>
            </span>

            <div className="composer-preset-chips">
              <button
                type="button"
                className="preset-chip"
                onClick={() => handlePresetClick("Send an email to bob@example.com with the project update.")}
                disabled={isExecuting}
              >
                ✉️ Send Project Update
              </button>
              <button
                type="button"
                className="preset-chip"
                onClick={() => handlePresetClick("Audit previous ledger entries and confirm Merkle consistency.")}
                disabled={isExecuting}
              >
                🔍 Audit Ledger
              </button>
            </div>
          </div>

          <div className="composer-right-actions">
            <span className="composer-shortcut-hint">
              <kbd>↵</kbd> Send · <kbd>Shift</kbd>+<kbd>↵</kbd> Newline
            </span>

            <button
              type="button"
              className={`composer-send-btn ${value.trim() && !isExecuting ? "active" : ""}`}
              onClick={onSend}
              disabled={isExecuting || !value.trim()}
              aria-label="Send action to Agent-of-Record"
              title="Send (Enter)"
            >
              {isExecuting ? (
                <span className="composer-spinner" />
              ) : (
                <span className="send-icon" aria-hidden="true">↑</span>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
