import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Route, Routes, Navigate } from 'react-router-dom';
import { Shell } from './components/Shell';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';

const Overview     = lazy(() => import('./pages/Overview'));
const Corgis       = lazy(() => import('./pages/Corgis'));
const Certificates = lazy(() => import('./pages/Certificates'));
const Assignments  = lazy(() => import('./pages/Assignments'));
const VigilCA      = lazy(() => import('./pages/VigilCA'));
const ShepherdCAs  = lazy(() => import('./pages/ShepherdCAs'));
const Tools        = lazy(() => import('./pages/Tools'));
const Login        = lazy(() => import('./pages/Login'));
const Enroll       = lazy(() => import('./pages/Enroll'));
const Profile      = lazy(() => import('./pages/Profile'));
const AdminUsers   = lazy(() => import('./pages/AdminUsers'));

const Loading = <div style={{ padding: 24, color: 'var(--muted)' }}>Loading…</div>;

export default function App(): React.ReactElement {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Suspense fallback={Loading}>
          <Routes>
            {/* Public routes */}
            <Route path="/login"          element={<Login />} />
            <Route path="/enroll/:token"  element={<Enroll />} />

            {/* Protected routes — wrapped in Shell */}
            <Route path="/*" element={
              <ProtectedRoute>
                <Shell>
                  <Suspense fallback={Loading}>
                    <Routes>
                      <Route path="/"             element={<Overview />} />
                      <Route path="/corgis"       element={<Corgis />} />
                      <Route path="/certificates" element={<Certificates />} />
                      <Route path="/assignments"  element={<Assignments />} />
                      <Route path="/shepherd-cas" element={<ShepherdCAs />} />
                      <Route path="/vigil-ca"     element={<VigilCA />} />
                      <Route path="/tools/*"      element={<Tools />} />
                      <Route path="/profile"      element={<Profile />} />
                      <Route path="/admin/users"  element={<AdminUsers />} />
                      <Route path="*"             element={<Navigate to="/" replace />} />
                    </Routes>
                  </Suspense>
                </Shell>
              </ProtectedRoute>
            } />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </AuthProvider>
  );
}
