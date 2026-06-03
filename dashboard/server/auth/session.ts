import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import type { DashboardAuthConfig } from '../config';

export type SessionUser = {
  userId: string;
  shepherdAccount: string;  // account `name` in shepherd.accounts.json
  identityUri: string;      // vigil:// URI from enrollment cert
  displayName: string;
  role: 'admin' | 'operator' | 'readonly';
  roleVerifiedAt: number;   // Date.now()
};

declare module 'express-session' {
  interface SessionData {
    user?: SessionUser;
  }
}

const FileStore = FileStoreFactory(session);

export function createSessionMiddleware(auth: DashboardAuthConfig) {
  return session({
    secret: auth.sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: new FileStore({
      path: auth.sessionsDir,
      ttl: auth.sessionDurationHours * 3600,
      reapInterval: 3600,
      logFn: () => {},
    }),
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: auth.sessionDurationHours * 60 * 60 * 1000,
    },
  });
}
