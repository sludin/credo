import { describe, it, expect } from 'vitest';
import { visibleColumns, type ColumnDef } from './columns';

type Row = { id: string };
type Key = 'a' | 'b' | 'c';

const COLUMNS: ColumnDef<Key, Row>[] = [
  { key: 'a', header: 'A', pinned: true, sortable: true, render: () => null },
  { key: 'b', header: 'B', sortable: true, render: () => null },
  { key: 'c', header: 'C', sortable: false, render: () => null },
];

describe('visibleColumns', () => {
  it('always keeps pinned columns even when not in the visible set', () => {
    expect(visibleColumns(COLUMNS, new Set<Key>()).map((c) => c.key)).toEqual(['a']);
  });

  it('includes non-pinned columns only when present in the visible set, preserving registry order', () => {
    expect(visibleColumns(COLUMNS, new Set<Key>(['c', 'b'])).map((c) => c.key)).toEqual(['a', 'b', 'c']);
  });

  it('ignores keys in the visible set that do not match any column', () => {
    expect(visibleColumns(COLUMNS, new Set(['not-a-key'] as unknown as Key[])).map((c) => c.key)).toEqual(['a']);
  });
});
