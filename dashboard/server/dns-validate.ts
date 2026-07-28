// A conservative hostname/FQDN shape check: labels of 1-63 alphanumeric-or-
// hyphen characters (no leading/trailing hyphen), dot-separated, optional
// trailing dot. Used before a caller-supplied hostname is ever passed to
// `dig` as a positional argument — `dig` interprets a leading `@`, `+`, or
// `-` as a directive/flag rather than a query name regardless of argv
// position, so this must be checked before execFile, not relied on to be
// "just a query name" by convention.
const HOSTNAME_PATTERN =
  /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.?$/;

export function isValidHostname(hostname: string): boolean {
  return hostname.length > 0 && hostname.length <= 253 && HOSTNAME_PATTERN.test(hostname);
}
