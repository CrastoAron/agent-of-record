import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "../context/RouterContext";
import ForgotPasswordModal from "./ForgotPasswordModal";

export default function LoginPage() {
  const { login, isAuthenticated, authError, clearError } = useAuth();
  const { navigate } = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [validationError, setValidationError] = useState("");
  const [forgotModalOpen, setForgotModalOpen] = useState(false);

  // If already authenticated, redirect immediately to dashboard
  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard");
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    clearError();
  }, []);

  const validateForm = () => {
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
      setValidationError("Please enter your password.");
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
      await login(email, password);
      navigate("/dashboard");
    } catch (err) {
      // Error handled via authError or thrown exception
    } finally {
      setLoading(false);
    }
  };

  const handleFillDemo = () => {
    setEmail("user@example.com");
    setPassword("password123");
    setValidationError("");
    clearError();
  };

  return (
    <div className="auth-page-container">
      <div className="auth-card card">
        <div className="auth-header text-center">
          <div className="auth-icon-wrapper">
            <span className="auth-icon">🔑</span>
          </div>
          <h1 className="auth-title">Welcome Back</h1>
          <p className="auth-subtitle">Sign in to your Agent-of-Record account</p>
        </div>

        {(validationError || authError) && (
          <div className="alert alert-error" role="alert">
            <span>⚠️ {validationError || authError}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          {/* Email Field */}
          <div className="form-group">
            <label htmlFor="login-email" className="form-label">
              Email Address
            </label>
            <div className="input-wrapper">
              <span className="input-prefix-icon" aria-hidden="true"></span>
              <input
                id="login-email"
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

          {/* Password Field */}
          <div className="form-group">
            <div className="label-with-link">
              <label htmlFor="login-password" className="form-label">
                Password
              </label>
              <button
                type="button"
                className="link-btn"
                onClick={() => setForgotModalOpen(true)}
              >
                Forgot password?
              </button>
            </div>

            <div className="input-wrapper">
              <span className="input-prefix-icon" aria-hidden="true"></span>
              <input
                id="login-password"
                type={showPassword ? "text" : "password"}
                className="form-control with-icon with-suffix"
                placeholder="••••••••"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (validationError) setValidationError("");
                }}
                required
                autoComplete="current-password"
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

          {/* Submit Button */}
          <button
            type="submit"
            className="btn btn-primary btn-block btn-lg"
            disabled={loading}
          >
            {loading ? (
              <span className="spinner-wrapper">
                <span className="spinner"></span> Signing in...
              </span>
            ) : (
              "Sign In"
            )}
          </button>
        </form>

        {/* Demo Fill Helper */}
        <div className="auth-helper-row">
          <button
            type="button"
            className="btn btn-ghost btn-xs fill-demo-btn"
            onClick={handleFillDemo}
          >
            ✨ Autofill Demo Credentials
          </button>
        </div>

        {/* Signup Redirect Footer */}
        <div className="auth-footer text-center">
          <p className="text-muted">
            Don't have an account?{" "}
            <button
              type="button"
              className="link-btn highlight"
              onClick={() => navigate("/signup")}
            >
              Sign up
            </button>
          </p>
        </div>
      </div>

      {/* Forgot Password Modal */}
      <ForgotPasswordModal
        isOpen={forgotModalOpen}
        onClose={() => setForgotModalOpen(false)}
      />
    </div>
  );
}
