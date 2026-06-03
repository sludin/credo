// src/components/Shell.tsx
import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { usePermission } from '../hooks/usePermission';

type NavItem = {
  to: string;
  icon: string;
  label: string;
};

type SidebarSection = {
  label: string;
  items: NavItem[];
};

const sections: SidebarSection[] = [
  {
    label: 'Overview',
    items: [{ to: '/', icon: '◈', label: 'Dashboard' }],
  },
  {
    label: 'Shepherd',
    items: [
      { to: '/corgis', icon: '⬡', label: 'Corgis' },
      { to: '/certificates', icon: '⬢', label: 'Certificates' },
      { to: '/assignments', icon: '≡', label: 'Assignments' },
      { to: '/shepherd-cas', icon: '⬡', label: 'CAs' },
    ],
  },
  {
    label: 'Vigil',
    items: [{ to: '/vigil-ca', icon: '⊙', label: 'CA' }],
  },
  {
    label: 'Tools',
    items: [
      { to: '/tools/dns-txt', icon: '⚙', label: 'DNS TXT Checker' },
      { to: '/tools/cert-viewer', icon: '⬧', label: 'Cert Viewer' },
    ],
  },
];

type TopbarProps = {
  title: string;
  subtitle?: string;
  secondsAgo?: number;
  onRefresh?: () => void;
  actions?: React.ReactNode;
};

export function Topbar({ title, subtitle, secondsAgo, onRefresh, actions }: TopbarProps): React.ReactElement {
  const agoLabel = secondsAgo === undefined ? null : secondsAgo === 0 ? 'just now' : `${secondsAgo}s ago`;
  return (
    <div className="topbar">
      <span className="topbar-title">{title}</span>
      {subtitle && <span className="topbar-sub">— {subtitle}</span>}
      <div className="topbar-spacer" />
      {actions}
      {agoLabel !== null && <span className="topbar-ago">Last polled {agoLabel}</span>}
      {onRefresh && <button className="btn btn-ghost btn-sm" onClick={onRefresh}>↺ Refresh</button>}
    </div>
  );
}

type ShellProps = {
  children: React.ReactNode;
};

export function Shell({ children }: ShellProps): React.ReactElement {
  const { user, refresh } = useAuth();
  const canManageUsers = usePermission('user:manage');
  const navigate = useNavigate();

  async function handleLogout(): Promise<void> {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    await refresh();
    navigate('/login');
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-mark">C</div>
          <span className="logo-text">Credo</span>
        </div>
        {sections.map((section) => (
          <div className="sidebar-section" key={section.label}>
            <div className="sidebar-label">{section.label}</div>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}
              >
                <span className="nav-icon">{item.icon}</span>
                {item.label}
              </NavLink>
            ))}
          </div>
        ))}
        {(canManageUsers) && (
          <div className="sidebar-section">
            <div className="sidebar-label">Admin</div>
            <NavLink to="/admin/users" className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}>
              <span className="nav-icon">👥</span>Users
            </NavLink>
          </div>
        )}
        <div className="sidebar-footer">
          <NavLink to="/profile" className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}>
            <span className="nav-icon">⚙</span>
            <span style={{ flex: 1 }}>{user?.displayName ?? 'Profile'}</span>
            {user && <span style={{ fontSize: 10, opacity: 0.6 }}>{user.role}</span>}
          </NavLink>
          <button className="nav-item" style={{ width: '100%', textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer' }} onClick={() => void handleLogout()}>
            <span className="nav-icon">↩</span>Sign out
          </button>
        </div>
      </aside>
      <div className="main-area">{children}</div>
    </div>
  );
}
