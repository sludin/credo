// src/hooks/useColumnVisibility.ts
import { useEffect, useState } from 'react';

type UseColumnVisibilityResult<K extends string> = {
  visible: Set<K>;
  toggle: (key: K) => void;
  isVisible: (key: K) => boolean;
};

export function readStored<K extends string>(storageKey: string, defaultVisible: readonly K[]): Set<K> {
  try {
    const raw = localStorage.getItem(storageKey);
    if (raw) return new Set(JSON.parse(raw) as K[]);
  } catch {
    // malformed JSON or storage unavailable (e.g. private browsing) — fall back to defaults
  }
  return new Set(defaultVisible);
}

/** Persists a set of visible column keys to localStorage, namespaced by `storageKey`. */
export function useColumnVisibility<K extends string>(
  storageKey: string,
  defaultVisible: readonly K[],
): UseColumnVisibilityResult<K> {
  const [visible, setVisible] = useState<Set<K>>(() => readStored(storageKey, defaultVisible));

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify([...visible]));
    } catch {
      // storage unavailable — visibility just won't persist across reloads
    }
  }, [storageKey, visible]);

  function toggle(key: K): void {
    setVisible((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return { visible, toggle, isVisible: (key: K) => visible.has(key) };
}
