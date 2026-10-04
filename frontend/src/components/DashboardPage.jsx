import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "../context/RouterContext";
import ChatInterface from "./ChatInterface";
import { API_BASE, authService } from "../services/authService.js";

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const { navigate, dashboardTab, setDashboardTab } = useRouter();
  const workspace = dashboardTab || "chat";
  const [prompts, setPrompts] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  useEffect(() => {
    document.body.classList.add("dashboard-active");
    document.documentElement.classList.add("dashboard-active");
    return () => {
      document.body.classList.remove("dashboard-active");
      document.documentElement.classList.remove("dashboard-active");
    };
  }, []);

  useEffect(() => {
    let active = true;
    if (workspace === "history") {
      setLoadingHistory(true);
      fetch(`${API_BASE}/api/prompts`, { headers: authService.getAuthHeaders() })
        .then((response) => (response.ok ? response.json() : { prompts: [] }))
        .then((data) => {
          if (active) setPrompts(data.prompts || []);
        })
        .catch(() => {
          if (active) setPrompts([]);
        })
        .finally(() => {
          if (active) setLoadingHistory(false);
        });
    }
    return () => {
      active = false;
    };
  }, [workspace]);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="dashboard-chat-page-container">
      <ChatInterface
        workspace={workspace}
        onSelectWorkspace={setDashboardTab}
        prompts={prompts}
        loadingHistory={loadingHistory}
        user={user}
        onLogout={handleLogout}
      />
    </div>
  );
}
