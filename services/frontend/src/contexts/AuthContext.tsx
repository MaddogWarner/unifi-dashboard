import { createContext, useCallback, useContext, useState } from "react";
import type { ReactNode } from "react";
import { getCurrentUser } from "../lib/api";
import { useTheme } from "./ThemeContext";
import type { Theme } from "./ThemeContext";

interface AuthContextType {
  token: string | null;
  login: (token: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("auth_token"));
  const { setTheme } = useTheme();

  const login = useCallback(async (nextToken: string) => {
    localStorage.setItem("auth_token", nextToken);
    setToken(nextToken);
    const user = await getCurrentUser();
    setTheme(user.theme === "dark" ? "dark" : ("light" as Theme));
  }, [setTheme]);

  const logout = useCallback(() => {
    localStorage.removeItem("auth_token");
    setToken(null);
    setTheme("light");
  }, [setTheme]);

  return (
    <AuthContext.Provider value={{ token, login, logout, isAuthenticated: Boolean(token) }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
