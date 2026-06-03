import { useAuth, type Role } from '../context/AuthContext';

const ROLE_ORDER: Role[] = ['readonly', 'operator', 'admin'];

const PERMISSIONS: Record<string, Role> = {
  'cert:view':         'readonly',
  'cert:renew':        'operator',
  'cert:delete':       'admin',
  'assignment:view':   'readonly',
  'assignment:create': 'operator',
  'assignment:edit':   'operator',
  'assignment:delete': 'admin',
  'corgi:view':        'readonly',
  'vigil:view':        'readonly',
  'vigil:issue':       'operator',
  'user:view':         'operator',
  'user:manage':       'admin',
  'config:view':       'operator',
  'config:manage':     'admin',
};

export function usePermission(action: string): boolean {
  const { user } = useAuth();
  if (!user) return false;
  const required = PERMISSIONS[action];
  if (!required) return false;
  return ROLE_ORDER.indexOf(user.role) >= ROLE_ORDER.indexOf(required);
}

export function hasPermission(role: Role | undefined, action: string): boolean {
  if (!role) return false;
  const required = PERMISSIONS[action];
  if (!required) return false;
  return ROLE_ORDER.indexOf(role) >= ROLE_ORDER.indexOf(required);
}
