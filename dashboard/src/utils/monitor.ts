// Endpoint-monitor helpers: corgi TLS-handshakes each configured endpoint and
// reports whether the served leaf matches the installed cert.
import type { MonitorEndpoint, MonitorStatus } from '../types';

export function monitorTone(status: MonitorStatus): 'green' | 'yellow' | 'red' | 'muted' {
  if (status === 'ok') return 'green';
  if (status === 'cert-mismatch') return 'red';
  if (status === 'unreachable' || status === 'partial-success') return 'yellow';
  return 'muted';
}

export function monitorLabel(status: MonitorStatus): string {
  switch (status) {
    case 'ok': return 'OK';
    case 'cert-mismatch': return 'Cert Mismatch';
    case 'unreachable': return 'Unreachable';
    case 'pending': return 'Pending';
    case 'partial-success': return 'Partial';
    default: return 'Unmonitored';
  }
}

/** Deep-link to the Cert Monitor Check tool, pre-loaded for a given cert. */
export function monitorCheckUrl(certName: string): string {
  return `/tools/cert-monitor-check?cert=${encodeURIComponent(certName)}`;
}

export type MonitorFormFields = {
  host: string;
  port: string;
  protocol: 'https' | 'tls';
};

export function monitorToForm(endpoint: MonitorEndpoint | undefined): MonitorFormFields {
  if (!endpoint) return { host: '', port: '443', protocol: 'https' };
  return { host: endpoint.host, port: String(endpoint.port), protocol: endpoint.protocol };
}

/** Blank host means unmonitored — the assignment carries no monitor block. */
export function monitorFromForm(
  host: string,
  port: string,
  protocol: 'https' | 'tls',
): MonitorEndpoint | undefined {
  const trimmed = host.trim();
  if (!trimmed) return undefined;
  const portNum = Number(port.trim());
  return {
    host: trimmed,
    port: Number.isInteger(portNum) && portNum > 0 && portNum <= 65535 ? portNum : 443,
    protocol,
  };
}
