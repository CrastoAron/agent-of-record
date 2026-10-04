import { useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "../context/RouterContext";

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  const { navigate } = useRouter();

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      navigate("/login");
    }
  }, [isAuthenticated, loading, navigate]);

  if (loading) {
    return (
      <div className="loading-screen text-center">
        <div className="spinner"></div>
        <p className="text-muted" style={{ marginTop: "1rem" }}>Authenticating session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null; // Will redirect via useEffect
  }

  return children;
}
