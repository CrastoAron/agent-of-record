import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "../context/RouterContext";

export default function SignupPage() {
  const { signup, isAuthenticated, authError, clearError } = useAuth();
  const { navigate } = useRouter();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [loading, setLoading] = useState(false);
  const [validationError, setValidationError] = useState("");

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard");
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    clearError();
  }, []);

  const validateForm = () => {
    if (!name.trim()) {
      setValidationError("Please enter your full name.");
      return false;
    }
    if (!email.trim()) {
      setValidationError("Please enter your email address.");
      return false;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setValidationError("Please enter a valid email address.");
      return false;
    }
    if (!password) {
      setValidationError("Please enter a password.");
      return false;
    }
    if (password.length < 6) {
      setValidationError("Password must be at least 6 characters long.");
      return false;
    }
    if (password !== confirmPassword) {
      setValidationError("Passwords do not match.");
      return false;
    }
    setValidationError("");
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);
    setValidationError("");

    try {
      await signup({ name, email, password });
      navigate("/dashboard");
    } catch (err) {
      // Error handled by AuthContext or error state
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page-container">
      <div className="auth-card card">
        <div className="auth-header text-center">
          <div className="auth-icon-wrapper">
            <span className="auth-icon">🚀</span>
          </div>
          <h1 className="auth-title">Create your Account</h1>
          <p className="auth-subtitle">Join Agent-of-Record for secure intent verification</p>
        </div>

        {(validationError || authError) && (
          <div className="alert alert-error" role="alert">
            <span>⚠️ {validationError || authError}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          {/* Full Name */}
          <div className="form-group">
            <label htmlFor="signup-name" className="form-label">
              Full Name
            </label>
            <div className="input-wrapper">
              <span className="input-prefix-icon" aria-hidden="true">👤</span>
              <input
                id="signup-name"
                type="text"
                className="form-control with-icon"
                placeholder="Alex Morgan"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (validationError) setValidationError("");
                }}
                required
                autoComplete="name"
              />
            </div>
          </div>

          {/* Email */}
          <div className="form-group">
            <label htmlFor="signup-email" className="form-label">
              Email Address
            </label>
            <div className="input-wrapper">
              <span className="input-prefix-icon" aria-hidden="true">✉️</span>
              <input
                id="signup-email"
                type="email"
                className="form-control with-icon"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (validationError) setValidationError("");
                }}
                required
                autoComplete="email"
              />
            </div>
          </div>

          {/* Password */}
          <div className="form-group">
            <label htmlFor="signup-password" className="form-label">
              Password
            </label>
            <div className="input-wrapper">
              <span className="input-prefix-icon" aria-hidden="true">🔒</span>
              <input
                id="signup-password"
                type={showPassword ? "text" : "password"}
                className="form-control with-icon with-suffix"
                placeholder="At least 6 characters"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (validationError) setValidationError("");
                }}
                required
                autoComplete="new-password"
              />
              <button
                type="button"
                className="password-toggle-btn"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? "🙈" : "👁️"}
              </button>
            </div>
          </div>

          {/* Confirm Password */}
          <div className="form-group">
            <label htmlFor="signup-confirm-password" className="form-label">
              Confirm Password
            </label>
            <div className="input-wrapper">
              <span className="input-prefix-icon" aria-hidden="true">🛡️</span>
              <input
                id="signup-confirm-password"
                type={showConfirmPassword ? "text" : "password"}
                className="form-control with-icon with-suffix"
                placeholder="Re-enter password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (validationError) setValidationError("");
                }}
                required
                autoComplete="new-password"
              />
              <button
                type="button"
                className="password-toggle-btn"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                title={showConfirmPassword ? "Hide password" : "Show password"}
              >
                {showConfirmPassword ? "🙈" : "👁️"}
              </button>
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="btn btn-primary btn-block btn-lg"
            disabled={loading}
          >
            {loading ? (
              <span className="spinner-wrapper">
                <span className="spinner"></span> Creating Account...
              </span>
            ) : (
              "Create Account"
            )}
          </button>
        </form>

        {/* Login Redirect Footer */}
        <div className="auth-footer text-center">
          <p className="text-muted">
            Already have an account?{" "}
            <button
              type="button"
              className="link-btn highlight"
              onClick={() => navigate("/login")}
            >
              Log in
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
