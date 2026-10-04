import { useState } from "react";
import { useAuth } from "../context/AuthContext";

export default function ForgotPasswordModal({ isOpen, onClose }) {
  const { resetPassword } = useAuth();
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email || !email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    setError("");
    setLoading(true);

    try {
      await resetPassword(email);
      setSuccess(true);
    } catch (err) {
      setError(err.message || "Failed to request password reset.");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setEmail("");
    setSuccess(false);
    setError("");
    onClose();
  };

  return (
    <div
      className="modal-overlay"
      onClick={handleReset}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div
        className="modal-content card"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h3 id="modal-title" className="modal-title">Reset Password</h3>
          <button
            type="button"
            className="modal-close-btn"
            onClick={handleReset}
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {success ? (
          <div className="modal-body text-center">
            <div className="status-badge pass" style={{ fontSize: "2rem", margin: "1rem auto", width: "fit-content" }}>
              ✓
            </div>
            <h4>Reset Link Sent!</h4>
            <p className="text-muted" style={{ marginTop: "0.5rem" }}>
              If an account is associated with <strong>{email}</strong>, we have sent instructions to reset your password.
            </p>
            <button
              type="button"
              className="btn btn-primary btn-block"
              style={{ marginTop: "1.5rem" }}
              onClick={handleReset}
            >
              Back to Login
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="modal-body">
            <p className="text-muted" style={{ marginBottom: "1rem" }}>
              Enter your email address and we'll send you a link to reset your password.
            </p>

            {error && (
              <div className="alert alert-error" role="alert">
                <span>⚠️ {error}</span>
              </div>
            )}

            <div className="form-group">
              <label htmlFor="reset-email" className="form-label">Email Address</label>
              <input
                id="reset-email"
                type="email"
                className="form-control"
                placeholder="name@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={handleReset}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={loading}
              >
                {loading ? "Sending..." : "Send Reset Link"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
