// src/lib/columns.ts
import type { ReactNode } from 'react';

export type ColumnDef<K extends string, Row> = {
  key: K;
  header: string;
  /** Pinned columns are always shown and don't appear in the visibility menu. */
  pinned?: boolean;
  sortable: boolean;
  sortValue?: (row: Row) => string | number;
  render: (row: Row) => ReactNode;
};

/** Keeps pinned columns plus any explicitly-visible ones, in registry order. */
export function visibleColumns<K extends string, Row>(
  all: ColumnDef<K, Row>[],
  visible: ReadonlySet<K>,
): ColumnDef<K, Row>[] {
  return all.filter((c) => c.pinned || visible.has(c.key));
}
