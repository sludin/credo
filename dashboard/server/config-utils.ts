import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// ${VAR} interpolation — resolves placeholders against a lookup table
// ---------------------------------------------------------------------------

function interpolate(value: string, lookup: Record<string, string>, serverName: string): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, name) => {
    const key = name.trim();
    if (key in lookup) return lookup[key];
    throw new Error(`${serverName} config references undefined variable: \${${key}}`);
  });
}

export function deepInterpolate(obj: unknown, lookup: Record<string, string>, serverName: string): unknown {
  if (typeof obj === 'string') return interpolate(obj, lookup, serverName);
  if (Array.isArray(obj)) return obj.map((v) => deepInterpolate(v, lookup, serverName));
  if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj as Record<string, unknown>).map(([k, v]) => [k, deepInterpolate(v, lookup, serverName)])
    );
  }
  return obj;
}

export function resolveVars(rawVars: Record<string, unknown>, serverName: string): Record<string, string> {
  const resolved: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(rawVars)) {
    if (rawValue === null || typeof rawValue === 'object') {
      throw new Error(`${serverName} config vars.${key} must be a string or scalar, not an object/array`);
    }
    const stringValue = String(rawValue);
    const lookup: Record<string, string> = { ...process.env as Record<string, string>, ...resolved };
    resolved[key] = interpolate(stringValue, lookup, `${serverName} vars`);
  }
  return resolved;
}

export function buildLookup(raw: Record<string, unknown>, serverName: string): Record<string, string> {
  const rawVars = raw['vars'];
  const vars = rawVars && typeof rawVars === 'object' && !Array.isArray(rawVars)
    ? resolveVars(rawVars as Record<string, unknown>, serverName)
    : {};
  return { ...process.env as Record<string, string>, ...vars };
}

// ---------------------------------------------------------------------------
// File includes — top-level `includes` array with deep merge
// ---------------------------------------------------------------------------

function deepMerge(base: Record<string, unknown>, override: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null && typeof value === 'object' && !Array.isArray(value) &&
      result[key] !== null && typeof result[key] === 'object' && !Array.isArray(result[key])
    ) {
      result[key] = deepMerge(result[key] as Record<string, unknown>, value as Record<string, unknown>);
    } else {
      result[key] = value;
    }
  }
  return result;
}

export function resolveIncludes(
  raw: Record<string, unknown>,
  filePath: string,
  _stack?: Set<string>
): Record<string, unknown> {
  const absPath = path.resolve(filePath);
  const stack = _stack ?? new Set([absPath]);
  const includes = raw['includes'];
  if (!Array.isArray(includes) || includes.length === 0) {
    return raw;
  }

  const fileDir = path.dirname(absPath);
  let merged: Record<string, unknown> = {};

  for (const include of includes) {
    if (typeof include !== 'string' || !include.trim()) continue;
    const includePath = path.resolve(fileDir, include.trim());
    if (stack.has(includePath)) {
      throw new Error(`Circular include detected: ${includePath} (included from ${absPath})`);
    }
    if (!fs.existsSync(includePath)) {
      throw new Error(`Include file not found: ${includePath} (referenced from ${absPath})`);
    }
    const includedRaw = JSON.parse(fs.readFileSync(includePath, 'utf8')) as Record<string, unknown>;
    const newStack = new Set([...stack, includePath]);
    merged = deepMerge(merged, resolveIncludes(includedRaw, includePath, newStack));
  }

  const { includes: _omit, ...rest } = raw;
  return deepMerge(merged, rest);
}

// ---------------------------------------------------------------------------
// Type coercion helpers
// ---------------------------------------------------------------------------

export function assertString(value: unknown, field: string, serverName = 'config'): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${serverName} config field '${field}' must be a non-empty string`);
  }
  return value.trim();
}

export function optionalString(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim()) {
    return undefined;
  }
  return value.trim();
}

export function intFromEnv(envVal: string | undefined, fallback: number): number {
  const parsed = Number(envVal);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

export function intFromRaw(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

export function boolFromEnv(envVal: string | undefined, fallback: boolean): boolean {
  if (envVal === undefined) {
    return fallback;
  }
  const normalized = envVal.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') {
    return true;
  }
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') {
    return false;
  }
  return fallback;
}

export function boolFromRaw(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') {
      return true;
    }
    if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') {
      return false;
    }
  }
  return fallback;
}

export type LogLevel = 'fatal' | 'warn' | 'info' | 'debug';

export function logLevelFrom(value: unknown, envOverride?: string): LogLevel {
  const resolved = (envOverride || String(value || 'info')).trim().toLowerCase();
  if (resolved === 'fatal' || resolved === 'warn' || resolved === 'info' || resolved === 'debug') {
    return resolved;
  }
  return 'info';
}

export function resolveMaybe(baseDir: string, filePath: string | undefined): string | undefined {
  if (!filePath) {
    return undefined;
  }
  return path.isAbsolute(filePath) ? filePath : path.resolve(baseDir, filePath);
}

export function resolveRequired(baseDir: string, filePath: string | undefined, field: string): string {
  const resolved = resolveMaybe(baseDir, filePath);
  if (!resolved) {
    throw new Error(`config field '${field}' must be a non-empty string`);
  }
  return resolved;
}

// ---------------------------------------------------------------------------
// Config file loader
// ---------------------------------------------------------------------------

export function loadConfigFile(envVar: string, defaultFile: string, serverName: string): unknown {
  const configPath = path.resolve(process.env[envVar] || path.join(process.cwd(), defaultFile));
  if (!fs.existsSync(configPath)) {
    throw new Error(`${serverName} config file not found at ${configPath}`);
  }
  const raw = JSON.parse(fs.readFileSync(configPath, 'utf8')) as Record<string, unknown>;
  const resolved = resolveIncludes(raw, configPath);
  const lookup = buildLookup(resolved, serverName);
  return deepInterpolate(resolved, lookup, serverName);
}
