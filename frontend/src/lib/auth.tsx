import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, onAuthError, setCsrf } from "./api";
import { setTimezone } from "./format";

export interface User {
  id: number; username: string; full_name: string; email?: string;
  roles: { name: string; display_name: string }[]; permissions: string[];
  must_change_password: boolean; last_login_at?: string;
}
interface AuthState {
  user: User | null; loading: boolean;
  can: (perm: string) => boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}
const Ctx = createContext<AuthState>(null as unknown as AuthState);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const loadSettings = async () => {
    try { const s = await api.get("/api/settings"); setTimezone(s.data.display_timezone); } catch { /* ignore */ }
  };
  const refresh = useCallback(async () => {
    try {
      const r = await api.get("/api/auth/me");
      setCsrf(r.data.csrf_token); setUser(r.data.user);
      if (!r.data.user.must_change_password) loadSettings();
    } catch { setUser(null); } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    refresh();
    onAuthError((e) => {
      if (e.status === 401) setUser(null);
      if (e.code === "password_change_required") setUser((u) => (u ? { ...u, must_change_password: true } : u));
    });
  }, [refresh]);

  const login = async (username: string, password: string) => {
    const r = await api.post("/api/auth/login", { username, password });
    setCsrf(r.data.csrf_token); setUser(r.data.user);
    if (!r.data.user.must_change_password) loadSettings();
  };
  const logout = async () => {
    try { await api.post("/api/auth/logout"); } finally { setCsrf(null); setUser(null); }
  };
  const can = (perm: string) => !!user?.permissions.includes(perm);
  return <Ctx.Provider value={{ user, loading, can, login, logout, refresh }}>{children}</Ctx.Provider>;
}
export const useAuth = () => useContext(Ctx);
