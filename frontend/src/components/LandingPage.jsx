import { useRouter } from "../context/RouterContext";
import { useAuth } from "../context/AuthContext";

export default function LandingPage() {
  const { navigate } = useRouter();
  const { isAuthenticated, user } = useAuth();

  return (
    <div className="landing-container">
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-badge">
          <span className="badge-dot"></span> Secure Auth & Intent Provenance
        </div>
        <h1 className="hero-title">
          Modern Authentication <br />
          <span className="gradient-text">Built for Speed & Security</span>
        </h1>
        <p className="hero-subtitle">
            Experience secure onboarding with SQLite-backed accounts, expiring
            sessions, and cryptographically traceable prompt actions.
        </p>

        <div className="hero-cta-group">
          {isAuthenticated ? (
            <button
              type="button"
              className="btn btn-primary btn-lg"
              onClick={() => navigate("/dashboard")}
            >
              Go to Dashboard →
            </button>
          ) : (
            <>
              <button
                type="button"
                className="btn btn-primary btn-lg"
                onClick={() => navigate("/signup")}
              >
                Get Started Free →
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-lg"
                onClick={() => navigate("/login")}
              >
                Log In to Account
              </button>
            </>
          )}
        </div>

        {/* Demo Credentials Quick-Notice */}
        <div className="demo-credentials-card">
          <div className="demo-badge">💡 Demo Credentials</div>
          <div className="demo-details">
            <div><strong>Email:</strong> <code>user@example.com</code></div>
            <div><strong>Password:</strong> <code>password123</code></div>
          </div>
        </div>
      </section>

      {/* Feature Section */}
      <section id="features" className="features-section">
        <div className="section-header">
          <h2 className="section-title">Designed for Next-Gen Web Apps</h2>
          <p className="section-subtitle">
            Clean architecture, modular authentication layer, and accessible UI components.
          </p>
        </div>

        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">🔒</div>
            <h3 className="feature-title">Separated Auth Layer</h3>
            <p className="feature-text">
              AuthContext and decoupled AuthService keep state logic isolated, making backend integration painless.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">👁️</div>
            <h3 className="feature-title">Password Visibility & Validation</h3>
            <p className="feature-text">
              Real-time validation, show/hide password toggles, and clear inline error notifications.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🛡️</div>
            <h3 className="feature-title">Protected Routes</h3>
            <p className="feature-text">
              Automatic route guarding redirects unauthenticated visitors safely to the login portal.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">⚡</div>
            <h3 className="feature-title">SQLite Persistence</h3>
            <p className="feature-text">
              Accounts, sessions, prompts, artifacts, and verification traces are
              persisted by the FastAPI backend.
            </p>
          </div>
        </div>
      </section>

      {/* CTA Footer Section */}
      <section className="cta-banner">
        <div className="cta-content">
          <h2>Ready to test out the portal?</h2>
          <p>Create an account or sign in with the demo account to view your protected dashboard.</p>
          <div className="cta-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => navigate(isAuthenticated ? "/dashboard" : "/signup")}
            >
              {isAuthenticated ? "View Dashboard" : "Create Free Account"}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
