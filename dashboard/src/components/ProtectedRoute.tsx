import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function ProtectedRoute({ children }: { children: React.ReactNode }): React.ReactElement {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <div style={{ padding: 24, color: 'var(--muted)' }}>Checking session…</div>;
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
