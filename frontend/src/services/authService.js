// Backend-backed authentication client for the React application.

const API_BASE = import.meta.env.VITE_VERIFIER_API_URL ?? "http://127.0.0.1:8000";
const TOKEN_KEY = "aor_auth_token";
const USER_KEY = "aor_auth_user";

async function responseJson(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Authentication request failed.");
  return data;
}

function persist(data) {
  localStorage.setItem(TOKEN_KEY, data.token);
  localStorage.setItem(USER_KEY, JSON.stringify(data.user));
  return data.user;
}

export const authService = {
  getCurrentUser() {
    try {
      const value = localStorage.getItem(USER_KEY);
      return value ? JSON.parse(value) : null;
    } catch {
      return null;
    }
  },

  getToken() {
    return localStorage.getItem(TOKEN_KEY);
  },

  getAuthHeaders(extra = {}) {
    const token = authService.getToken();
    return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
  },

  async restoreSession() {
    if (!authService.getToken()) return null;
    try {
      const response = await fetch(`${API_BASE}/api/auth/me`, {
        headers: authService.getAuthHeaders(),
      });
      if (!response.ok) {
        authService.clearSession();
        return null;
      }
      const data = await response.json();
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      return data.user;
    } catch {
      return authService.getCurrentUser();
    }
  },

  async login(email, password) {
    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    return persist(await responseJson(response));
  },

  async signup({ name, email, password }) {
    const response = await fetch(`${API_BASE}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password }),
    });
    return persist(await responseJson(response));
  },

  async resetPassword(email) {
    const response = await fetch(`${API_BASE}/api/auth/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    return responseJson(response);
  },

  async logout() {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        headers: authService.getAuthHeaders(),
      });
    } finally {
      authService.clearSession();
    }
  },

  clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

export { API_BASE };
