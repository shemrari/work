import { createContext, ReactNode, useContext, useEffect, useState } from 'react';

type AuthContextValue = {
  email: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

async function readError(response: Response) {
  const body = await response.json().catch(() => null);
  return typeof body?.detail === 'string' ? body.detail : `Request failed (${response.status})`;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [email, setEmail] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const restoreSession = async () => {
      try {
        const response = await fetch('/auth/session', { credentials: 'same-origin' });
        const session = response.ok ? await response.json() : { authenticated: false };
        if (mounted) setEmail(session.authenticated ? session.email : null);
      } catch {
        if (mounted) setEmail(null);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    void restoreSession();
    return () => { mounted = false; };
  }, []);

  const login = async (username: string, password: string) => {
    const response = await fetch('/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) throw new Error(await readError(response));
    const result = await response.json();
    setEmail(result.email);
  };

  const logout = async () => {
    const response = await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    if (!response.ok) throw new Error(await readError(response));
    setEmail(null);
  };

  return <AuthContext.Provider value={{ email, loading, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}