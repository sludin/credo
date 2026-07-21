import { describe, it, expect, beforeEach } from 'vitest';
import { readStored } from './useColumnVisibility';

class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.get(key) ?? null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}

beforeEach(() => {
  (globalThis as { localStorage?: unknown }).localStorage = new MemoryStorage();
});

describe('readStored', () => {
  it('falls back to defaults when nothing is stored', () => {
    expect(readStored('k', ['a', 'b'])).toEqual(new Set(['a', 'b']));
  });

  it('returns the stored set when present', () => {
    localStorage.setItem('k', JSON.stringify(['a', 'c']));
    expect(readStored('k', ['a', 'b'])).toEqual(new Set(['a', 'c']));
  });

  it('falls back to defaults on malformed JSON', () => {
    localStorage.setItem('k', '{not json');
    expect(readStored('k', ['a', 'b'])).toEqual(new Set(['a', 'b']));
  });

  it('falls back to defaults when localStorage is unavailable', () => {
    (globalThis as { localStorage?: unknown }).localStorage = undefined;
    expect(readStored('k', ['a', 'b'])).toEqual(new Set(['a', 'b']));
  });
});
