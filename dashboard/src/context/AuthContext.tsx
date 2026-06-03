import React, { createContext, useContext, useEffect, useState } from 'react';

export type Role = 'admin' | 'operator' | 'readonly';

export type AuthUser = {
  userId: string;
  shepherdAccount: string;
  displayName: string;
  role: Role;
};

type AuthState = {
  user: AuthUser | null;
  loading: boolean;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  refresh: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async (): Promise<void> => {
    try {
      const resp = await fetch('/auth/me', { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json() as { user: AuthUser };
        setUser(data.user);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, []);

  return (
    <AuthContext.Provider value={{ user, loading, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
