import { useState } from "react";
import ClientSigning from "./components/ClientSigning";
import VerificationPortal from "./components/VerificationPortal";
import "./styles.css";

export default function App() {
  const [activeTab, setActiveTab] = useState("signing");

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-container">
          <div className="brand">
            <span className="logo-icon">🛡️</span>
            <div className="brand-text">
              <span className="brand-name">Agent-of-Record</span>
              <span className="brand-tagline">Cryptographic Intent & Evidence Provenance</span>
            </div>
          </div>
          <nav className="nav-tabs" aria-label="Main Navigation">
            <button
              type="button"
              className={`tab-btn ${activeTab === "signing" ? "active" : ""}`}
              onClick={() => setActiveTab("signing")}
            >
              <span className="tab-icon">✍️</span> Client Signing
            </button>
            <button
              type="button"
              className={`tab-btn ${activeTab === "portal" ? "active" : ""}`}
              onClick={() => setActiveTab("portal")}
            >
              <span className="tab-icon">🔍</span> Verification Portal
            </button>
          </nav>
        </div>
      </header>

      <main className="main-content">
        {activeTab === "signing" && <ClientSigning />}
        {activeTab === "portal" && <VerificationPortal />}
      </main>

      <footer className="app-footer">
        <div className="footer-container">
          <p>
            Agent-of-Record (AoR) Protocol · RFC 8785 (JCS) · SHA3-256 · ECDSA P-256 / Ed25519
          </p>
        </div>
      </footer>
    </div>
  );
}
