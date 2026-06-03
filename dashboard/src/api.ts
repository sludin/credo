// src/api.ts
import type {
  AssignmentsPayload,
  CasPayload,
  CertChainPayload,
  CertStorePayload,
  CertX509Details,
  FlockPayload,
  HealthPayload,
  LastRenewalJob,
  ShepherdConfigSummary,
  VigilCAPayload,
  VigilCertsPayload,
} from './types';

async function requestJson<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(options?.headers ?? {}),
    },
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error((payload as { error?: string }).error ?? `Request failed: ${response.status}`);
  }
  return payload as T;
}

// ── Shepherd ──────────────────────────────────────────────────────────────
export function fetchHealth(): Promise<HealthPayload> {
  return requestJson<HealthPayload>('/api/health');
}

export function fetchFlock(): Promise<FlockPayload> {
  return requestJson<FlockPayload>('/api/flock');
}

export function fetchCerts(): Promise<CertStorePayload> {
  return requestJson<CertStorePayload>('/api/certs');
}

export function fetchAssignments(): Promise<AssignmentsPayload> {
  return requestJson<AssignmentsPayload>('/api/assignments');
}

export function fetchShepherdConfigSummary(): Promise<ShepherdConfigSummary> {
  return requestJson<ShepherdConfigSummary>('/api/admin/config-summary');
}

export function renewCert(certName: string, corgiName: string): Promise<unknown> {
  return requestJson('/api/certs/' + encodeURIComponent(certName) + '/renew', {
    method: 'POST',
    body: JSON.stringify({ corgiName }),
  });
}

/** Returns the raw PEM string for a cert by name (live cert from certstore). */
export async function fetchCertPem(certName: string): Promise<string> {
  const response = await fetch('/api/certs/' + encodeURIComponent(certName) + '/pem');
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(payload.error ?? `Failed to fetch PEM: ${response.status}`);
  }
  return response.text();
}

/** Returns server-parsed X509 details (including PEM) for a cert. */
export function fetchCertDetails(certName: string): Promise<CertX509Details> {
  return requestJson<CertX509Details>('/api/certs/' + encodeURIComponent(certName) + '/details');
}

/** Returns the last terminal renewal job for a cert, or null if none exists. */
export function fetchLastJob(certName: string): Promise<LastRenewalJob | null> {
  return requestJson<{ job: LastRenewalJob | null }>('/api/certs/' + encodeURIComponent(certName) + '/last-job')
    .then(r => r.job);
}

/** Returns the current active (non-terminal) renewal job for a cert, or null. */
export function fetchActiveJob(certName: string): Promise<LastRenewalJob | null> {
  return requestJson<{ job: LastRenewalJob | null }>('/api/certs/' + encodeURIComponent(certName) + '/active-job')
    .then(r => r.job);
}

export function createAssignment(data: Record<string, unknown>): Promise<unknown> {
  return requestJson('/api/assignments', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function updateAssignment(
  certName: string,
  data: Record<string, unknown>,
  matchCorgi?: string,
): Promise<unknown> {
  const body = matchCorgi ? { ...data, matchCorgi } : data;
  return requestJson('/api/assignments/' + encodeURIComponent(certName), {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

export function deleteAssignment(certName: string, matchCorgi?: string): Promise<unknown> {
  const body = matchCorgi ? JSON.stringify({ matchCorgi }) : undefined;
  return requestJson('/api/assignments/' + encodeURIComponent(certName), {
    method: 'DELETE',
    body,
  });
}

// ── CA config ─────────────────────────────────────────────────────────────
export function fetchCas(): Promise<CasPayload> {
  return requestJson<CasPayload>('/api/admin/cas');
}

export function updateCa(name: string, payload: Record<string, unknown>): Promise<unknown> {
  return requestJson('/api/admin/cas/' + encodeURIComponent(name), {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export function deleteCa(name: string): Promise<void> {
  return requestJson('/api/admin/cas/' + encodeURIComponent(name), { method: 'DELETE' });
}

// ── Vigil ─────────────────────────────────────────────────────────────────
export function fetchVigilCA(): Promise<VigilCAPayload> {
  return requestJson<VigilCAPayload>('/api/vigil/ca');
}

export function fetchVigilCerts(): Promise<VigilCertsPayload> {
  return requestJson<VigilCertsPayload>('/api/vigil/certs');
}

// ── DNS Tools ──────────────────────────────────────────────────────────────
export interface DnsUpdateResult {
  success: boolean;
  message?: string;
  error?: string;
}

export interface DnsToolConfigResult {
  pollingIntervalSeconds: number;
  publicResolvers: Array<{ name: string; ip: string }>;
}

export interface DnsJobResolverResult {
  name: string;
  ip: string;
  role: 'authoritative' | 'public';
  txtRecords: string[];
  queriedAt: string;
  error?: string;
}

export interface DnsJobResponse {
  jobId: string;
  hostname: string;
  targetValue: string;
  results: DnsJobResolverResult[];
  converged: boolean;
  startedAt: string;
  elapsedMs: number;
}

export function fetchDnsToolConfig(): Promise<DnsToolConfigResult> {
  return requestJson<DnsToolConfigResult>('/api/dns/config');
}

export function createDnsJob(hostname: string, targetValue: string): Promise<DnsJobResponse> {
  return requestJson<DnsJobResponse>('/api/dns/jobs', {
    method: 'POST',
    body: JSON.stringify({ hostname, targetValue }),
  });
}

export function pollDnsJob(jobId: string): Promise<DnsJobResponse> {
  return requestJson<DnsJobResponse>(`/api/dns/jobs/${encodeURIComponent(jobId)}`);
}

export function updateTxtRecord(payload: {
  certName: string;
  hostname: string;
  txtValue: string;
}): Promise<DnsUpdateResult> {
  return requestJson<DnsUpdateResult>('/api/dns/txt', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ── Cert Viewer ────────────────────────────────────────────────────────────
export function fetchShepherdCertFull(certName: string): Promise<CertChainPayload> {
  return requestJson<CertChainPayload>('/api/certs/' + encodeURIComponent(certName) + '/full');
}

export function fetchRemoteCert(host: string, port: number): Promise<CertChainPayload> {
  return requestJson<CertChainPayload>(
    `/api/cert-remote?host=${encodeURIComponent(host)}&port=${port}`,
  );
}
