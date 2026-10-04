import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "../context/RouterContext";

export default function Navbar() {
  const { user, isAuthenticated, logout } = useAuth();
  const { currentPath, navigate } = useRouter();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const isDashboard = currentPath === "/dashboard";

  return (
    <header className={`app-header ${isDashboard ? "dashboard-header" : ""}`}>
      <div className={`header-container ${isDashboard ? "dashboard-header-container" : ""}`}>
        {/* Brand Logo */}
        <div
          className="brand"
          onClick={() => navigate("/")}
          style={{ cursor: "pointer" }}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === "Enter" && navigate("/")}
        >
          <span className="logo-icon" aria-hidden="true">🛡️</span>
          <div className="brand-text">
            <span className="brand-name">Agent-of-Record</span>
            <span className="brand-tagline">Secure Authentication & Provenance</span>
          </div>
        </div>

        {/* Mobile Toggle Button */}
        <button
          type="button"
          className="mobile-toggle-btn"
          aria-label="Toggle navigation menu"
          aria-expanded={mobileMenuOpen}
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          {mobileMenuOpen ? "✕" : "☰"}
        </button>

        {/* Global Navigation Links */}
        <nav
          className={`nav-menu ${mobileMenuOpen ? "mobile-open" : ""}`}
          aria-label="Main Navigation"
        >
          <button
            type="button"
            className={`nav-link ${currentPath === "/" ? "active" : ""}`}
            onClick={() => {
              navigate("/");
              setMobileMenuOpen(false);
            }}
          >
            Home
          </button>
          
          <a
            href="#features"
            className="nav-link"
            onClick={(e) => {
              e.preventDefault();
              if (currentPath !== "/") {
                navigate("/");
                setTimeout(() => {
                  document.getElementById("features")?.scrollIntoView({ behavior: "smooth" });
                }, 100);
              } else {
                document.getElementById("features")?.scrollIntoView({ behavior: "smooth" });
              }
              setMobileMenuOpen(false);
            }}
          >
            Features
          </a>

          {isAuthenticated ? (
            <div className="auth-nav-group">
              {!isDashboard && (
                <button
                  type="button"
                  className={`nav-link ${currentPath === "/dashboard" ? "active" : ""}`}
                  onClick={() => {
                    navigate("/dashboard");
                    setMobileMenuOpen(false);
                  }}
                >
                  Dashboard
                </button>
              )}
              <div className="user-badge" title={user?.email || ""}>
                <span className="user-avatar">{user?.name ? user.name[0].toUpperCase() : "U"}</span>
                <span className="user-name-short">{user?.name || "User"}</span>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleLogout}
              >
                Log Out
              </button>
            </div>
          ) : (
            <div className="auth-nav-group">
              <button
                type="button"
                className={`btn btn-ghost ${currentPath === "/login" ? "active" : ""}`}
                onClick={() => {
                  navigate("/login");
                  setMobileMenuOpen(false);
                }}
              >
                Log In
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  navigate("/signup");
                  setMobileMenuOpen(false);
                }}
              >
                Get Started
              </button>
            </div>
          )}
        </nav>
      </div>
    </header>
  );
}
