// Blocks the classic SSRF targets — loopback and link-local (which includes
// the 169.254.169.254 cloud-metadata service on AWS/GCP/Azure) — for any
// dashboard feature that connects to a caller-supplied host. Deliberately
// does NOT block RFC1918 private ranges: this dashboard's whole purpose is
// inspecting TLS certs on an internal fleet, which normally *is* on private
// addresses (10.x/172.16.x/192.168.x) — blocking those would break the
// feature's ordinary use, not just the attack case. Loopback/link-local are
// never a legitimate target for "check this fleet member's cert."
export function isBlockedSsrfTarget(ip: string): boolean {
  if (ip.includes(':')) {
    return isBlockedIpv6(ip);
  }
  return isBlockedIpv4(ip);
}

function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = octets;
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local (incl. cloud metadata)
  if (a === 0) return true; // "this network" / unspecified
  return false;
}

function isBlockedIpv6(rawIp: string): boolean {
  // Strip a zone index (e.g. "fe80::1%eth0") before normalizing.
  const ip = rawIp.split('%')[0].toLowerCase();
  if (ip === '::1') return true; // loopback
  if (ip === '::') return true; // unspecified
  // Link-local unicast fe80::/10 — first 10 bits are 1111111010.
  if (/^fe[89ab][0-9a-f]:/.test(ip)) return true;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — check the embedded IPv4 address too.
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIpv4(mapped[1]);
  return false;
}
