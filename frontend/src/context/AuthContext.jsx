import { createContext, useContext, useState, useEffect } from "react";
import { authService } from "../services/authService";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState(null);

  useEffect(() => {
    let mounted = true;
    authService.restoreSession().then((activeSession) => {
      if (mounted) {
        setUser(activeSession);
        setLoading(false);
      }
    });
    return () => { mounted = false; };
  }, []);

  const login = async (email, password) => {
    setAuthError(null);
    try {
      const loggedInUser = await authService.login(email, password);
      setUser(loggedInUser);
      return loggedInUser;
    } catch (err) {
      setAuthError(err.message);
      throw err;
    }
  };

  const signup = async ({ name, email, password }) => {
    setAuthError(null);
    try {
      const newUser = await authService.signup({ name, email, password });
      setUser(newUser);
      return newUser;
    } catch (err) {
      setAuthError(err.message);
      throw err;
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    setAuthError(null);
  };

  const resetPassword = async (email) => {
    setAuthError(null);
    try {
      return await authService.resetPassword(email);
    } catch (err) {
      setAuthError(err.message);
      throw err;
    }
  };

  const clearError = () => {
    setAuthError(null);
  };

  const value = {
    user,
    isAuthenticated: !!user,
    loading,
    authError,
    login,
    signup,
    logout,
    resetPassword,
    clearError
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
