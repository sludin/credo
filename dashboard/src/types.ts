// src/types.ts

// ── Health ────────────────────────────────────────────────────────────────
export type ServiceHealth = {
  status: string;
  service?: string;
};

export type HealthPayload = {
  dashboard: { status: string };
  shepherdApi: ServiceHealth;
  shepherdCorgi: ServiceHealth;
};

// ── Flock (Corgi + certs) ─────────────────────────────────────────────────
export type FlockCert = {
  name: string;
  lifetimeDays: number;
  status: 'ok' | 'not-ok';
  sanNames: string[];
  fingerprint256?: string;
  validTo?: string;
};

export type CorgiState = {
  name: string;
  url: string;
  status: 'reachable' | 'unreachable' | 'unknown';
  lastPolledAt?: string;
  error?: string;
  flock: FlockCert[];
};

export type FlockPayload = {
  corgis: CorgiState[];
};

// ── Cert store ────────────────────────────────────────────────────────────
export type CertStoreAssignment = {
  corgi: string;
  ca: string;
  domain?: string;
};

export type CertStoreEntry = {
  certName: string;
  archiveDir: string;
  liveDir: string;
  exists: boolean;
  latestOrdinal: string | null;
  archiveFiles: string[];
  live: Record<string, string | null>;
  assignment?: CertStoreAssignment;
};

export type CertStorePayload = {
  certStoreDir: string;
  entries: CertStoreEntry[];
};

// ── Assignments ───────────────────────────────────────────────────────────
export type AssignmentValidation = {
  type?: 'auto' | 'none-01' | 'http-01' | 'dns-01';
  methods?: {
    'dns-01'?: {
      provider?: string;
      providerConfig?: Record<string, unknown>;
    };
    'http-01'?: Record<string, unknown>;
    'none-01'?: Record<string, unknown>;
  };
};

export type Assignment = {
  corgi: string;
  certName: string;
  ca?: string;
  caTarget?: string;
  letsEncryptTarget?: string;
  domain?: string;
  identityUri?: string;
  sans?: string[];
  renewBeforeDays?: number;
  days?: number;
  fingerprint256?: string;
  validation?: AssignmentValidation;
  monitor?: boolean;
};

export type AssignmentsPayload = {
  assignments: Assignment[];
};

export type ShepherdConfigSummary = {
  cas: Array<{
    name: string;
    protocol: string;
    provider?: string | null;
    defaultValidation?: string | null;
    validationProviders?: Record<string, string>;
  }>;
};

// ── CA config ─────────────────────────────────────────────────────────────
export type CaDetail = {
  name: string;
  protocol: string;
  provider?: string | null;
  directoryUrl?: string;
  accountEmail?: string;
  accountKeyPath?: string;
  renewBeforeDays?: number | null;
  days?: number | null;
  defaultValidation?: string | null;
  supportedValidations?: string[];
  validationDns01Provider?: string | null;
  validationDns01DdnsKey?: string | null;
  validationDns01PropagationDelaySeconds?: number | null;
  tlsCertPath?: string | null;
  tlsKeyPath?: string | null;
  tlsCaPath?: string | null;
  insecureSkipVerify?: boolean;
};

export type CasPayload = { cas: CaDetail[] };

// ── Vigil CA ──────────────────────────────────────────────────────────────
export type VigilCAInfo = {
  subject: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  certPem?: string;
};

export type VigilCAPayload = {
  rootCA: VigilCAInfo;
};

export type VigilIssuedCert = {
  id: string;
  serialNumber: string;
  subject: string;
  fingerprint256: string;
  validFrom: string;
  validTo: string;
  issuedAt: string;
  revoked: boolean;
  revokedAt?: string;
};

export type VigilCertsPayload = {
  certificates: VigilIssuedCert[];
  stats: { total: number; active: number; revoked: number };
};

// ── Cert X509 details (server-parsed from PEM) ───────────────────────────
export type CertX509Details = {
  pem: string;
  subject: string;
  issuer: string;
  subjectAltName: string | null;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  fingerprint256: string;
  ca: boolean;
};

// ── Cert detail (derived client-side) ────────────────────────────────────
export type CertDetail = {
  certName: string;
  corgi: string;
  ca: string;
  domain: string;
  sanNames: string[];
  daysLeft: number;
  validTo: string;
  status: 'ok' | 'not-ok' | 'expiring';
  fingerprint256: string;
};

export type RenewalTraceEntry = {
  at: string;
  step: string;
  detail?: string;
  identifier?: string;
  status?: string;
};

export type LastRenewalJob = {
  id: string;
  certName: string;
  phase: string;
  startedAt: string;
  updatedAt: string;
  error?: string;
  result?: { issued: boolean; changed: boolean; fingerprint256?: string };
  trace: RenewalTraceEntry[];
  // Present on active (non-terminal) jobs
  currentDomain?: string | null;
  domainStatus?: Record<string, string>;
  domains?: string[];
};

// ── Cert Viewer ───────────────────────────────────────────────────────────

export type CertField = {
  label: string;
  value: string | string[];
  display?: 'mono' | 'hex' | 'pills' | 'text';
  critical?: boolean;
};

export type CertSection = {
  title: string;
  fields: CertField[];
  subsections?: CertSection[];
};

export type ParsedCertFull = {
  pem: string;
  textView: string;
  daysLeft: number;
  sections: CertSection[];
};

export type CertChainEntry = {
  index: number;
  role: 'leaf' | 'intermediate';
  commonName: string;
  validTo: string;
  cert: ParsedCertFull;
};

export type RootEntry = {
  role: 'root';
  commonName: string;
  received: false;
};

export type CertChainPayload = {
  host: string;
  port: number;
  chain: CertChainEntry[];
  root: RootEntry;
};
