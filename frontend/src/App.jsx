import { AuthProvider } from "./context/AuthContext";
import { RouterProvider, useRouter } from "./context/RouterContext";
import Navbar from "./components/Navbar";
import LandingPage from "./components/LandingPage";
import LoginPage from "./components/LoginPage";
import SignupPage from "./components/SignupPage";
import DashboardPage from "./components/DashboardPage";
import ProtectedRoute from "./components/ProtectedRoute";
import "./styles.css";

function AppContent() {
  const { currentPath } = useRouter();

  const renderView = () => {
    switch (currentPath) {
      case "/":
        return <LandingPage />;
      case "/login":
        return <LoginPage />;
      case "/signup":
        return <SignupPage />;
      case "/dashboard":
        return (
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        );
      default:
        return <LandingPage />;
    }
  };

  const isDashboard = currentPath === "/dashboard";

  return (
    <div className={`app-shell ${isDashboard ? "dashboard-mode" : ""}`}>
      <Navbar />
      <main className={`main-content ${isDashboard ? "dashboard-main" : ""}`}>{renderView()}</main>
      {!isDashboard && (
        <footer className="app-footer">
          <div className="footer-container">
            <p>
              Agent-of-Record (AoR) Protocol · Mock Authentication System · Built with React & CSS
            </p>
          </div>
        </footer>
      )}
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <RouterProvider>
        <AppContent />
      </RouterProvider>
    </AuthProvider>
  );
}
