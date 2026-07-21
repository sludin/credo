# Configurable Table Columns (Remaining Tables) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the configurable-columns feature (already shipped on Overview's Certificate Health table) to four more dashboard tables: Overview's Corgi Fleet, the outer corgi list on Corgis, the main cert list on Certificates, and the Vigil-Issued Certificates table on VigilCA.

**Architecture:** Extract the two pieces already duplicated by the shipped cert-health table — the `ColumnDef`/`visibleColumns` filtering logic and the "Columns ⚙" dropdown UI — into shared modules (`dashboard/src/lib/columns.ts`, `dashboard/src/components/ColumnMenu.tsx`). Each table keeps its own column-registry file and its own `useColumnVisibility` hook instance (independent localStorage key), following the exact pattern already proven on `certHealthColumns.tsx` / `Overview.tsx`.

**Tech Stack:** React + TypeScript (Vite), Vitest for unit tests (no React Testing Library in this repo — components are verified via `tsc`/`vite build`, not render tests). No new dependencies.

## Global Constraints

- Every column in every table defaults to **visible** (spec: "Defaults" section — no new hidden-by-default fields this round).
- `useColumnVisibility` (`dashboard/src/hooks/useColumnVisibility.ts`) is already generic and must not be modified.
- Storage keys follow `credo.columns.<page>.<table>` (spec's per-table plan table): `credo.columns.overview.corgiFleet`, `credo.columns.corgis.corgiList`, `credo.columns.certificates.list`, `credo.columns.vigil.issuedCerts`.
- Out of scope, do not touch: Corgis.tsx's inner per-corgi cert table (leave fully static, but its `colSpan` wrapper must still track the now-variable outer column count — see Task 5), `ShepherdCAs.tsx`, `CertViewer.tsx`, and the raw Vigil ledger fields (`serialNumber`, `issuedAt`, `revoked`).
- Every task must pass `cd dashboard && npm run typecheck` and `npm test` before committing (the repo's pre-commit hook enforces `npm run typecheck` on any `dashboard/` change — do not bypass with `--no-verify`).
- No component-rendering tests are added (matches existing repo convention — no RTL/jsdom installed). Presentational-only changes (`ColumnMenu.tsx`, page JSX) are verified via typecheck + `npm run build`, not new test files.

---

### Task 1: Extract generic column-visibility filtering into `lib/columns.ts`

**Files:**
- Create: `dashboard/src/lib/columns.ts`
- Create: `dashboard/src/lib/columns.test.ts`
- Modify: `dashboard/src/pages/certHealthColumns.tsx`

**Interfaces:**
- Produces: `ColumnDef<K extends string, Row>` type — `{ key: K; header: string; pinned?: boolean; sortable: boolean; sortValue?: (row: Row) => string | number; render: (row: Row) => React.ReactNode }`. `visibleColumns<K extends string, Row>(all: ColumnDef<K, Row>[], visible: ReadonlySet<K>): ColumnDef<K, Row>[]` — keeps pinned columns unconditionally, plus any column whose key is in `visible`, preserving registry order. Every later task imports both from `../lib/columns` (or `../../lib/columns` from `components/`).

- [ ] **Step 1: Write the failing test**

Create `dashboard/src/lib/columns.test.ts`:

```ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd dashboard && npx vitest run src/lib/columns.test.ts`
Expected: FAIL — `Cannot find module './columns'`

- [ ] **Step 3: Write the implementation**

Create `dashboard/src/lib/columns.ts`:

```ts
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd dashboard && npx vitest run src/lib/columns.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Retrofit `certHealthColumns.tsx` to use the generic type/function**

In `dashboard/src/pages/certHealthColumns.tsx`, replace the local `CertColumn` type definition and the local `visibleCertColumns` implementation:

```tsx
// src/pages/certHealthColumns.tsx
import React from 'react';
import { StatusBadge, certTone } from '../components/StatusBadge';
import { monitorTone, monitorLabel } from '../utils/monitor';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import type { CertStoreEntry, FlockCert } from '../types';

export type CertColumnKey =
  | 'domain' | 'corgi' | 'ca' | 'daysLeft' | 'expires' | 'status'
  | 'monitorStatus' | 'monitorChecked' | 'fingerprint' | 'sanCount';

export type CertRow = { corgi: string; cert: FlockCert; store?: CertStoreEntry; daysLeft: number };

export type CertColumn = ColumnDef<CertColumnKey, CertRow>;
```

(The rest of the file — `fmtDate`, `certStatusLabel`, `CERT_COLUMNS`, `DEFAULT_VISIBLE_CERT_COLUMNS` — is unchanged.) Replace the final function:

```tsx
export function visibleCertColumns(visible: ReadonlySet<CertColumnKey>): CertColumn[] {
  return visibleColumns(CERT_COLUMNS, visible);
}
```

- [ ] **Step 6: Run the existing cert-health tests to confirm nothing broke**

Run: `cd dashboard && npx vitest run src/pages/certHealthColumns.test.ts`
Expected: PASS (5 tests, unchanged from before this task)

- [ ] **Step 7: Full verification**

Run: `cd dashboard && npm run typecheck && npm test`
Expected: both succeed, 0 errors, all tests passing

- [ ] **Step 8: Commit**

```bash
git add dashboard/src/lib/columns.ts dashboard/src/lib/columns.test.ts dashboard/src/pages/certHealthColumns.tsx
git commit -m "refactor(dashboard): extract generic column-visibility filter into lib/columns

Generalizes the ColumnDef type and visibleColumns filter out of
certHealthColumns.tsx so the four upcoming tables (Corgi Fleet,
Certificates, Vigil-Issued Certificates) can reuse it instead of
each re-implementing the same pinned-column filtering logic."
```

---

### Task 2: Shared `ColumnMenu` component, retrofit Overview's cert table to use it

**Files:**
- Create: `dashboard/src/components/ColumnMenu.tsx`
- Modify: `dashboard/src/pages/Overview.tsx:113-127` (cert table's card-header block)

**Interfaces:**
- Consumes: `ColumnDef<K, Row>` from `../lib/columns` (Task 1).
- Produces: `ColumnMenu<K extends string, Row>({ columns, visible, onToggle }: { columns: ColumnDef<K, Row>[]; visible: ReadonlySet<K>; onToggle: (key: K) => void }): React.ReactElement`. Every later table-retrofit task renders `<ColumnMenu columns={...} visible={...} onToggle={...} />` in place of a hand-rolled dropdown.

- [ ] **Step 1: Implement the component**

Create `dashboard/src/components/ColumnMenu.tsx`:

```tsx
// src/components/ColumnMenu.tsx
import React from 'react';
import type { ColumnDef } from '../lib/columns';

type ColumnMenuProps<K extends string, Row> = {
  columns: ColumnDef<K, Row>[];
  visible: ReadonlySet<K>;
  onToggle: (key: K) => void;
};

/** "Columns ⚙" trigger + checklist, reusing the existing .action-menu dropdown from theme.css. */
export function ColumnMenu<K extends string, Row>({ columns, visible, onToggle }: ColumnMenuProps<K, Row>): React.ReactElement {
  const toggleable = columns.filter((col) => !col.pinned);
  return (
    <details className="action-menu">
      <summary className="btn btn-ghost btn-sm">Columns ⚙</summary>
      <div className="action-menu-dropdown">
        {toggleable.map((col) => (
          <label key={col.key} className="action-menu-item" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" checked={visible.has(col.key)} onChange={() => onToggle(col.key)} />
            {col.header}
          </label>
        ))}
      </div>
    </details>
  );
}
```

- [ ] **Step 2: Retrofit Overview.tsx's cert table to use it**

In `dashboard/src/pages/Overview.tsx`, add the import:

```tsx
import { ColumnMenu } from '../components/ColumnMenu';
```

Replace the hand-rolled dropdown block:

```tsx
<details className="action-menu">
  <summary className="btn btn-ghost btn-sm">Columns ⚙</summary>
  <div className="action-menu-dropdown">
    {CERT_COLUMNS.filter((col) => !col.pinned).map((col) => (
      <label key={col.key} className="action-menu-item" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input type="checkbox" checked={isVisible(col.key)} onChange={() => toggleCertColumn(col.key)} />
        {col.header}
      </label>
    ))}
  </div>
</details>
```

with:

```tsx
<ColumnMenu columns={CERT_COLUMNS} visible={visibleCertColumnKeys} onToggle={toggleCertColumn} />
```

Since `isVisible` is no longer used anywhere in `Overview.tsx` after this change, drop it from the hook destructure:

```tsx
const { visible: visibleCertColumnKeys, toggle: toggleCertColumn } =
  useColumnVisibility(CERT_COLUMNS_STORAGE_KEY, DEFAULT_VISIBLE_CERT_COLUMNS);
```

- [ ] **Step 3: Full verification**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: all succeed. (No new tests — `ColumnMenu` is a thin presentational wrapper around already-tested `visibleColumns`/existing `.action-menu` CSS; verified via typecheck + build per this repo's convention of not adding component-render tests.)

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/ColumnMenu.tsx dashboard/src/pages/Overview.tsx
git commit -m "refactor(dashboard): extract shared ColumnMenu component

Replaces the hand-rolled Columns dropdown in Overview's cert table
with a reusable component so the four upcoming tables don't each
duplicate the same details/summary checklist markup."
```

---

### Task 3: `corgiColumns.tsx` registry (shared by Overview's Corgi Fleet and Corgis' outer list)

**Files:**
- Create: `dashboard/src/pages/corgiColumns.tsx`
- Create: `dashboard/src/pages/corgiColumns.test.ts`

**Interfaces:**
- Consumes: `ColumnDef`, `visibleColumns` from `../lib/columns` (Task 1); `CorgiState` from `../types`; `StatusBadge`, `serviceTone` from `../components/StatusBadge`.
- Produces: `CorgiColumnKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen' | 'services'` (note: `'services'` is included in the key type for Overview's page-specific extra column, but is **not** part of `CORGI_COLUMNS` itself — see Task 4). `CorgiRow = CorgiState`. `CorgiColumn = ColumnDef<CorgiColumnKey, CorgiRow>`. `CORGI_COLUMNS: CorgiColumn[]` (5 entries: name/host/status/certs/lastSeen). `DEFAULT_VISIBLE_CORGI_COLUMNS: CorgiColumnKey[]` (all 5). `visibleCorgiColumns(visible: ReadonlySet<CorgiColumnKey>): CorgiColumn[]`. `corgiHost(corgi: CorgiRow): string` (exported so Task 4's Services-column helper and Task 5 don't need to reimplement URL-hostname parsing).

- [ ] **Step 1: Write the failing test**

Create `dashboard/src/pages/corgiColumns.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { CORGI_COLUMNS, DEFAULT_VISIBLE_CORGI_COLUMNS, visibleCorgiColumns, corgiHost, type CorgiColumnKey } from './corgiColumns';

describe('visibleCorgiColumns', () => {
  it('always keeps the pinned name column, even when not in the visible set', () => {
    expect(visibleCorgiColumns(new Set<CorgiColumnKey>()).map((c) => c.key)).toEqual(['name']);
  });

  it('returns all 5 base columns for the default visibility set, in registry order', () => {
    const cols = visibleCorgiColumns(new Set(DEFAULT_VISIBLE_CORGI_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['name', 'host', 'status', 'certs', 'lastSeen']);
  });

  it('every column key in the base registry is reachable via visibility toggling', () => {
    const allKeys = CORGI_COLUMNS.map((c) => c.key);
    expect(visibleCorgiColumns(new Set(allKeys)).map((c) => c.key)).toEqual(allKeys);
  });
});

describe('corgiHost', () => {
  it('extracts the hostname from a well-formed URL', () => {
    expect(corgiHost({ url: 'https://corgi-a.internal:7001' } as Parameters<typeof corgiHost>[0])).toBe('corgi-a.internal');
  });

  it('falls back to the raw string when the URL is malformed', () => {
    expect(corgiHost({ url: 'not-a-url' } as Parameters<typeof corgiHost>[0])).toBe('not-a-url');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd dashboard && npx vitest run src/pages/corgiColumns.test.ts`
Expected: FAIL — `Cannot find module './corgiColumns'`

- [ ] **Step 3: Write the implementation**

Create `dashboard/src/pages/corgiColumns.tsx`:

```tsx
// src/pages/corgiColumns.tsx
import React from 'react';
import { StatusBadge, serviceTone } from '../components/StatusBadge';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import type { CorgiState } from '../types';

export type CorgiColumnKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen' | 'services';
export type CorgiRow = CorgiState;
export type CorgiColumn = ColumnDef<CorgiColumnKey, CorgiRow>;

export function corgiHost(corgi: CorgiRow): string {
  try {
    return new URL(corgi.url).hostname;
  } catch {
    return corgi.url;
  }
}

export const CORGI_COLUMNS: CorgiColumn[] = [
  {
    key: 'name', header: 'Name', pinned: true, sortable: true,
    sortValue: (r) => r.name,
    render: (r) => <td className="fw-500">{r.name}</td>,
  },
  {
    key: 'host', header: 'Host', sortable: true,
    sortValue: (r) => corgiHost(r),
    render: (r) => <td className="text-muted mono">{corgiHost(r)}</td>,
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (r) => r.status,
    render: (r) => {
      const tone = serviceTone(r.status);
      const label = r.status.charAt(0).toUpperCase() + r.status.slice(1);
      return <td><StatusBadge label={label} tone={tone} /></td>;
    },
  },
  {
    key: 'certs', header: 'Certs', sortable: true,
    sortValue: (r) => r.flock.length,
    render: (r) => <td>{r.flock.length}</td>,
  },
  {
    key: 'lastSeen', header: 'Last Seen', sortable: true,
    sortValue: (r) => (r.lastPolledAt ? new Date(r.lastPolledAt).getTime() : 0),
    render: (r) => <td className="text-muted">{r.lastPolledAt ? new Date(r.lastPolledAt).toLocaleTimeString() : '—'}</td>,
  },
];

export const DEFAULT_VISIBLE_CORGI_COLUMNS: CorgiColumnKey[] = ['name', 'host', 'status', 'certs', 'lastSeen'];

export function visibleCorgiColumns(visible: ReadonlySet<CorgiColumnKey>): CorgiColumn[] {
  return visibleColumns(CORGI_COLUMNS, visible);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd dashboard && npx vitest run src/pages/corgiColumns.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Full verification**

Run: `cd dashboard && npm run typecheck && npm test`
Expected: both succeed

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/pages/corgiColumns.tsx dashboard/src/pages/corgiColumns.test.ts
git commit -m "feat(dashboard): add shared corgi-columns registry

Base column set (Name/Host/Status/Certs/Last Seen) shared by both
Overview's Corgi Fleet table and Corgis' outer corgi list, which
render identical CorgiState data. Visibility state stays independent
per page (added in the next two tasks) — only the column
definitions are shared."
```

---

### Task 4: Overview.tsx Corgi Fleet table retrofit

**Files:**
- Modify: `dashboard/src/pages/Overview.tsx`

**Interfaces:**
- Consumes: `CORGI_COLUMNS`, `DEFAULT_VISIBLE_CORGI_COLUMNS`, `CorgiColumnKey`, `CorgiColumn` from `./corgiColumns` (Task 3); `visibleColumns` from `../lib/columns` (Task 1); `ColumnMenu` from `../components/ColumnMenu` (Task 2, already imported from Task 2).

- [ ] **Step 1: Add imports and the page-local Services column**

In `dashboard/src/pages/Overview.tsx`, add to the imports:

```tsx
import { visibleColumns } from '../lib/columns';
import { CORGI_COLUMNS, DEFAULT_VISIBLE_CORGI_COLUMNS, type CorgiColumnKey, type CorgiColumn } from './corgiColumns';
```

Remove the now-unused local `CorgiSortKey` type alias (`type CorgiSortKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen';`) and replace every remaining use of `CorgiSortKey` in the file with `CorgiColumnKey`.

Add a module-level helper (below the imports, alongside the existing `CERT_COLUMNS_STORAGE_KEY` constant):

```tsx
const CORGI_COLUMNS_STORAGE_KEY = 'credo.columns.overview.corgiFleet';

function buildServicesColumn(health: HealthPayload | null): CorgiColumn {
  return {
    key: 'services',
    header: 'Services',
    sortable: false,
    render: () => (
      <td>
        {health?.shepherdApi?.status && (
          <StatusBadge
            label={health.shepherdApi.status === 'healthy' ? 'API' : 'API down'}
            tone={serviceTone(health.shepherdApi.status)}
          />
        )}
      </td>
    ),
  };
}
```

- [ ] **Step 2: Wire up the hook and derived column list**

Inside the `Overview` component, add alongside the existing cert-column hook usage:

```tsx
const { visible: visibleCorgiColumnKeys, toggle: toggleCorgiColumn } =
  useColumnVisibility<CorgiColumnKey>(CORGI_COLUMNS_STORAGE_KEY, [...DEFAULT_VISIBLE_CORGI_COLUMNS, 'services']);
```

Near the existing `const visibleCols = visibleCertColumns(visibleCertColumnKeys);` line (or `visibleColumns(CERT_COLUMNS, ...)` if Task 1/2 already changed the call site), add:

```tsx
const overviewCorgiColumns: CorgiColumn[] = [...CORGI_COLUMNS, buildServicesColumn(health)];
const visibleCorgiCols = visibleColumns(overviewCorgiColumns, visibleCorgiColumnKeys);
```

- [ ] **Step 3: Replace the hardcoded sort switch**

Replace the hand-rolled `sortedCorgis` sort with a generic sortValue-driven comparator (mirroring how the cert table's sort was generalized):

```tsx
const corgiColumnByKey = new Map(overviewCorgiColumns.map((c) => [c.key, c]));

const sortedCorgis = [...corgis].sort((a, b) => {
  const sortValue = corgiColumnByKey.get(corgiSort.key)?.sortValue;
  if (!sortValue) return 0;
  const av = sortValue(a);
  const bv = sortValue(b);
  const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
  return corgiSort.dir === 'asc' ? cmp : -cmp;
});
```

This replaces the previous `aHost`/`bHost`/`aLast`/`bLast` + `switch (corgiSort.key)` block entirely.

- [ ] **Step 4: Replace the table JSX**

Replace the Corgi Fleet card's header and table body:

```tsx
{/* Corgi fleet table */}
<div className="card">
  <div className="card-header">
    <span className="card-title">Corgi Fleet</span>
    <span className="card-subtitle">{corgis.length} configured</span>
    <ColumnMenu columns={overviewCorgiColumns} visible={visibleCorgiColumnKeys} onToggle={toggleCorgiColumn} />
  </div>
  <div className="table-wrap">
    <table>
      <thead>
        <tr>
          {visibleCorgiCols.map((col) =>
            col.sortable ? (
              <th key={col.key} className="th-sort" onClick={() => toggleCorgiSort(col.key)}>
                {col.header} <span>{sortIndicator(corgiSort.key === col.key, corgiSort.dir)}</span>
              </th>
            ) : (
              <th key={col.key}>{col.header}</th>
            )
          )}
        </tr>
      </thead>
      <tbody>
        {sortedCorgis.length === 0 && (
          <tr>
            <td colSpan={visibleCorgiCols.length} className="text-muted" style={{ textAlign: 'center', padding: 20 }}>
              No corgis found
            </td>
          </tr>
        )}
        {sortedCorgis.map((corgi) => (
          <tr
            key={corgi.name}
            className="clickable"
            onClick={() => navigate(`/corgis?corgi=${encodeURIComponent(corgi.name)}`)}
          >
            {visibleCorgiCols.map((col) => (
              <React.Fragment key={col.key}>{col.render(corgi)}</React.Fragment>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
</div>
```

`toggleCorgiSort`'s parameter type comes from the existing `function toggleCorgiSort(key: CorgiSortKey)` declaration — since Step 1 already replaced every use of `CorgiSortKey` in the file with `CorgiColumnKey`, this signature now reads `function toggleCorgiSort(key: CorgiColumnKey): void` with no further edit needed here.

- [ ] **Step 5: Full verification**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: all succeed

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/pages/Overview.tsx
git commit -m "feat(dashboard): configurable columns for Overview's Corgi Fleet table

Same Columns ⚙ control as the cert-health table, using the shared
corgiColumns registry plus a page-local Services column (global
Shepherd API health, not per-row data, so it isn't part of the
shared registry). Independent localStorage key from the Corgis
page's identical-looking table."
```

---

### Task 5: Corgis.tsx outer corgi list retrofit

**Files:**
- Modify: `dashboard/src/pages/Corgis.tsx`

**Interfaces:**
- Consumes: `CORGI_COLUMNS`, `DEFAULT_VISIBLE_CORGI_COLUMNS`, `visibleCorgiColumns`, `CorgiColumnKey` from `./corgiColumns` (Task 3); `ColumnMenu` from `../components/ColumnMenu` (Task 2); `useColumnVisibility` from `../hooks/useColumnVisibility`.

**Important:** only the **outer** corgi-list table changes. The inner per-corgi cert table (lines ~156-227 in the current file) stays exactly as-is — do not add a Columns control there. Its wrapping `<td colSpan={5}>` does need to change to `<td colSpan={visibleCorgiCols.length}>` so it still spans the full (now variable) width of the outer row it sits under.

- [ ] **Step 1: Add imports and hook**

Add to the imports in `dashboard/src/pages/Corgis.tsx`:

```tsx
import { useColumnVisibility } from '../hooks/useColumnVisibility';
import { ColumnMenu } from '../components/ColumnMenu';
import { CORGI_COLUMNS, DEFAULT_VISIBLE_CORGI_COLUMNS, visibleCorgiColumns, type CorgiColumnKey } from './corgiColumns';
```

Remove the local `type CorgiSortKey = 'name' | 'host' | 'status' | 'certs' | 'lastSeen';` and replace its uses with `CorgiColumnKey` (the `certSort`/`CertSortKey` state for the inner table is untouched).

Inside the component, add:

```tsx
const { visible: visibleCorgiColumnKeys, toggle: toggleCorgiColumn } =
  useColumnVisibility<CorgiColumnKey>('credo.columns.corgis.corgiList', DEFAULT_VISIBLE_CORGI_COLUMNS);
```

- [ ] **Step 2: Replace the sort logic and derive the visible column list**

Replace the hand-rolled `sortedCorgis` sort:

```tsx
const corgiColumnByKey = new Map(CORGI_COLUMNS.map((c) => [c.key, c]));

const sortedCorgis = [...corgis].sort((a, b) => {
  const sortValue = corgiColumnByKey.get(corgiSort.key)?.sortValue;
  if (!sortValue) return 0;
  const av = sortValue(a);
  const bv = sortValue(b);
  const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
  return corgiSort.dir === 'asc' ? cmp : -cmp;
});
```

Add just above the `return`:

```tsx
const visibleCorgiCols = visibleCorgiColumns(visibleCorgiColumnKeys);
```

- [ ] **Step 3: Replace the outer table's header/header-cell and row rendering**

Update the card-header:

```tsx
<div className="card-header">
  <span className="card-title">Corgi Fleet</span>
  <span className="card-subtitle">{corgis.length} registered</span>
  <ColumnMenu columns={CORGI_COLUMNS} visible={visibleCorgiColumnKeys} onToggle={toggleCorgiColumn} />
</div>
```

Update the outer `<thead>`:

```tsx
<thead>
  <tr>
    <th style={{ width: 20 }} />
    {visibleCorgiCols.map((col) =>
      col.sortable ? (
        <th key={col.key} className="th-sort" onClick={() => toggleCorgiSort(col.key)}>
          {col.header} <span>{sortIndicator(corgiSort.key === col.key, corgiSort.dir)}</span>
        </th>
      ) : (
        <th key={col.key}>{col.header}</th>
      )
    )}
  </tr>
</thead>
```

Update the empty-state row's `colSpan` from `6` to `1 + visibleCorgiCols.length`.

Update the per-corgi row rendering — replace the five hardcoded `<td>` cells (`corgi.name`, `host`, `StatusBadge`, `corgi.flock.length`, `lastPolledAt`) with:

```tsx
{visibleCorgiCols.map((col) => (
  <React.Fragment key={col.key}>{col.render(corgi)}</React.Fragment>
))}
```

placed right after the existing expand-arrow `<td>`. Remove the now-unused `const tone = serviceTone(corgi.status);`, `const statusLabel = ...`, and `const host = ...` lines from that row's callback — they're no longer referenced there (the inner cert table below doesn't use them either).

Update the nested expanded-row wrapper's `colSpan` from the hardcoded `5` to `visibleCorgiCols.length`:

```tsx
{isExpanded && (
  <tr>
    <td />
    <td colSpan={visibleCorgiCols.length} style={{ padding: '0 0 8px 0' }}>
      {/* inner per-corgi cert table — unchanged */}
```

- [ ] **Step 4: Full verification**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: all succeed

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/pages/Corgis.tsx
git commit -m "feat(dashboard): configurable columns for Corgis' outer corgi list

Reuses the shared corgiColumns registry with its own independent
localStorage key. The inner per-corgi cert table is left untouched
per design decision, aside from its colSpan wrapper now tracking
the outer table's (now variable) visible column count."
```

---

### Task 6: `certificateListColumns.tsx` registry

**Files:**
- Modify: `dashboard/src/pages/Certificates.tsx` (export two existing internals)
- Create: `dashboard/src/pages/certificateListColumns.tsx`
- Create: `dashboard/src/pages/certificateListColumns.test.ts`

**Interfaces:**
- Consumes: `ColumnDef`, `visibleColumns` from `../lib/columns`; `StatusBadge` from `../components/StatusBadge`; `statusTone`, `statusLabel`, `UnifiedStatus` from `./Certificates.testable`; `UnifiedCertRow`, `fmtDate` newly exported from `./Certificates.tsx` (this task).
- Produces: `CertificateListColumnKey = 'name' | 'corgi' | 'ca' | 'status' | 'expires'`. `CERTIFICATE_LIST_COLUMNS: ColumnDef<CertificateListColumnKey, UnifiedCertRow>[]`. `DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS: CertificateListColumnKey[]` (all 5). `visibleCertificateListColumns(visible): ColumnDef<...>[]`.

- [ ] **Step 1: Export the two internals `certificateListColumns.tsx` needs**

In `dashboard/src/pages/Certificates.tsx`:
- Change `type UnifiedCertRow = {` to `export type UnifiedCertRow = {`.
- Change `function fmtDate(s: string | undefined | null): string {` to `export function fmtDate(s: string | undefined | null): string {`.

- [ ] **Step 2: Write the failing test**

Create `dashboard/src/pages/certificateListColumns.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  CERTIFICATE_LIST_COLUMNS,
  DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS,
  visibleCertificateListColumns,
  type CertificateListColumnKey,
} from './certificateListColumns';

describe('visibleCertificateListColumns', () => {
  it('always keeps the pinned name column, even when not in the visible set', () => {
    expect(visibleCertificateListColumns(new Set<CertificateListColumnKey>()).map((c) => c.key)).toEqual(['name']);
  });

  it('returns all 5 columns for the default visibility set, in registry order', () => {
    const cols = visibleCertificateListColumns(new Set(DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['name', 'corgi', 'ca', 'status', 'expires']);
  });

  it('every column key in the registry is reachable via visibility toggling', () => {
    const allKeys = CERTIFICATE_LIST_COLUMNS.map((c) => c.key);
    expect(visibleCertificateListColumns(new Set(allKeys)).map((c) => c.key)).toEqual(allKeys);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd dashboard && npx vitest run src/pages/certificateListColumns.test.ts`
Expected: FAIL — `Cannot find module './certificateListColumns'`

- [ ] **Step 4: Write the implementation**

Create `dashboard/src/pages/certificateListColumns.tsx`:

```tsx
// src/pages/certificateListColumns.tsx
import React from 'react';
import { StatusBadge } from '../components/StatusBadge';
import { statusTone, statusLabel } from './Certificates.testable';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import { fmtDate, type UnifiedCertRow } from './Certificates';

export type CertificateListColumnKey = 'name' | 'corgi' | 'ca' | 'status' | 'expires';

export type CertificateListColumn = ColumnDef<CertificateListColumnKey, UnifiedCertRow>;

export const CERTIFICATE_LIST_COLUMNS: CertificateListColumn[] = [
  {
    key: 'name', header: 'Name', pinned: true, sortable: true,
    sortValue: (r) => r.certName,
    render: (r) => <td className="fw-500">{r.domain}</td>,
  },
  {
    key: 'corgi', header: 'Corgi', sortable: true,
    sortValue: (r) => r.corgi,
    render: (r) => <td className="text-muted">{r.corgi}</td>,
  },
  {
    key: 'ca', header: 'CA', sortable: true,
    sortValue: (r) => r.ca,
    render: (r) => <td className="text-muted">{r.ca}</td>,
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (r) => r.status,
    render: (r) => (
      <td>
        <StatusBadge label={statusLabel(r.status, r.daysLeft)} tone={statusTone(r.status)} spinning={r.status === 'renewing'} />
      </td>
    ),
  },
  {
    key: 'expires', header: 'Expires', sortable: true,
    sortValue: (r) => r.daysLeft ?? Infinity,
    render: (r) => <td className="text-muted">{r.validTo ? fmtDate(r.validTo) : '—'}</td>,
  },
];

export const DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS: CertificateListColumnKey[] = ['name', 'corgi', 'ca', 'status', 'expires'];

export function visibleCertificateListColumns(visible: ReadonlySet<CertificateListColumnKey>): CertificateListColumn[] {
  return visibleColumns(CERTIFICATE_LIST_COLUMNS, visible);
}
```

Note: `sortValue` for `name`/`corgi`/`ca`/`status` intentionally does **not** lowercase (matches the exact existing comparison behavior in `Certificates.tsx` being replaced in Task 7 — no case-normalization was applied there before).

- [ ] **Step 5: Run test to verify it passes**

Run: `cd dashboard && npx vitest run src/pages/certificateListColumns.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 6: Full verification**

Run: `cd dashboard && npm run typecheck && npm test`
Expected: both succeed

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/pages/Certificates.tsx dashboard/src/pages/certificateListColumns.tsx dashboard/src/pages/certificateListColumns.test.ts
git commit -m "feat(dashboard): add certificate-list column registry

Name/Corgi/CA/Status/Expires columns for the Certificates page's
main table, matching its existing UnifiedCertRow shape and sort
comparisons exactly. Exports UnifiedCertRow and fmtDate from
Certificates.tsx so the registry can reuse them without duplication."
```

---

### Task 7: Certificates.tsx main table retrofit

**Files:**
- Modify: `dashboard/src/pages/Certificates.tsx`

**Interfaces:**
- Consumes: `CERTIFICATE_LIST_COLUMNS`, `DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS`, `CertificateListColumnKey` from `./certificateListColumns` (Task 6); `useColumnVisibility` from `../hooks/useColumnVisibility`; `ColumnMenu` from `../components/ColumnMenu` (Task 2).

- [ ] **Step 1: Add imports and hook, remove the duplicate SortKey union**

Add to the imports:

```tsx
import { useColumnVisibility } from '../hooks/useColumnVisibility';
import { ColumnMenu } from '../components/ColumnMenu';
import {
  CERTIFICATE_LIST_COLUMNS,
  DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS,
  type CertificateListColumnKey,
} from './certificateListColumns';
```

Replace `type SortKey = 'name' | 'corgi' | 'ca' | 'status' | 'expires';` with:

```tsx
type SortKey = CertificateListColumnKey;
```

Inside the component, add:

```tsx
const { visible: visibleCertListColumnKeys, toggle: toggleCertListColumn } =
  useColumnVisibility<CertificateListColumnKey>('credo.columns.certificates.list', DEFAULT_VISIBLE_CERTIFICATE_LIST_COLUMNS);
```

- [ ] **Step 2: Replace the sort switch**

Replace:

```tsx
const sorted = [...filtered].sort((a, b) => {
  let cmp = 0;
  switch (sort.key) {
    case 'name': cmp = a.certName.localeCompare(b.certName); break;
    case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
    case 'ca': cmp = a.ca.localeCompare(b.ca); break;
    case 'status': cmp = a.status.localeCompare(b.status); break;
    case 'expires': cmp = (a.daysLeft ?? Infinity) - (b.daysLeft ?? Infinity); break;
  }
  return sort.dir === 'asc' ? cmp : -cmp;
});
```

with:

```tsx
const certListColumnByKey = new Map(CERTIFICATE_LIST_COLUMNS.map((c) => [c.key, c]));

const sorted = [...filtered].sort((a, b) => {
  const sortValue = certListColumnByKey.get(sort.key)?.sortValue;
  if (!sortValue) return 0;
  const av = sortValue(a);
  const bv = sortValue(b);
  const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
  return sort.dir === 'asc' ? cmp : -cmp;
});
```

Add just above the `return`:

```tsx
const visibleCertListCols = visibleCertificateListColumns(visibleCertListColumnKeys);
```

(Import `visibleCertificateListColumns` alongside the other named imports from `./certificateListColumns` in Step 1.)

- [ ] **Step 3: Replace the filter-bar and table JSX**

Update the filter-bar:

```tsx
<div className="filter-bar">
  <input
    className="filter-input"
    placeholder="Filter by domain, cert name, or corgi…"
    value={filter}
    onChange={e => setFilter(e.target.value)}
  />
  <ColumnMenu columns={CERTIFICATE_LIST_COLUMNS} visible={visibleCertListColumnKeys} onToggle={toggleCertListColumn} />
</div>
```

Update the `<thead>`:

```tsx
<thead>
  <tr>
    {visibleCertListCols.map((col) => (
      <th key={col.key} className="th-sort" onClick={() => toggleSort(col.key)}>
        {col.header} <span>{sortIndicator(sort.key === col.key, sort.dir)}</span>
      </th>
    ))}
  </tr>
</thead>
```

(All 5 columns in `CERTIFICATE_LIST_COLUMNS` are sortable, so no plain-`<th>` branch is needed here.)

Update the empty-state `colSpan` from `5` to `visibleCertListCols.length`, and replace the row cells:

```tsx
{sorted.map(row => (
  <tr
    key={`${row.corgi}:${row.certName}`}
    className={`clickable${selectedCertName === row.certName ? ' expanded' : ''}`}
    onClick={() => handleSelectRow(row)}
  >
    {visibleCertListCols.map((col) => (
      <React.Fragment key={col.key}>{col.render(row)}</React.Fragment>
    ))}
  </tr>
))}
```

- [ ] **Step 4: Full verification**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: all succeed

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/pages/Certificates.tsx
git commit -m "feat(dashboard): configurable columns for the Certificates list table

Columns trigger added to the existing filter-bar since this page
has no card-header. Sort logic now driven generically by the
column registry's sortValue functions instead of a hand-written
switch, matching the pattern used on the other tables."
```

---

### Task 8: `vigilCertColumns.tsx` registry

**Files:**
- Create: `dashboard/src/pages/vigilCertColumns.tsx`
- Create: `dashboard/src/pages/vigilCertColumns.test.ts`

**Interfaces:**
- Consumes: `ColumnDef`, `visibleColumns` from `../lib/columns`; `StatusBadge`, `certTone` from `../components/StatusBadge`; `FlockCert` from `../types`.
- Produces: `VigilCertColumnKey = 'certName' | 'corgi' | 'domain' | 'daysLeft' | 'status'`. `VigilCertRow = { corgi: string; cert: FlockCert; daysLeft: number }`. `VIGIL_CERT_COLUMNS: ColumnDef<VigilCertColumnKey, VigilCertRow>[]`. `DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS: VigilCertColumnKey[]` (all 5). `visibleVigilCertColumns(visible): ColumnDef<...>[]`.

- [ ] **Step 1: Write the failing test**

Create `dashboard/src/pages/vigilCertColumns.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  VIGIL_CERT_COLUMNS,
  DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS,
  visibleVigilCertColumns,
  type VigilCertColumnKey,
} from './vigilCertColumns';

describe('visibleVigilCertColumns', () => {
  it('always keeps the pinned certName column, even when not in the visible set', () => {
    expect(visibleVigilCertColumns(new Set<VigilCertColumnKey>()).map((c) => c.key)).toEqual(['certName']);
  });

  it('returns all 5 columns for the default visibility set, in registry order', () => {
    const cols = visibleVigilCertColumns(new Set(DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS));
    expect(cols.map((c) => c.key)).toEqual(['certName', 'corgi', 'domain', 'daysLeft', 'status']);
  });

  it('every column key in the registry is reachable via visibility toggling', () => {
    const allKeys = VIGIL_CERT_COLUMNS.map((c) => c.key);
    expect(visibleVigilCertColumns(new Set(allKeys)).map((c) => c.key)).toEqual(allKeys);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd dashboard && npx vitest run src/pages/vigilCertColumns.test.ts`
Expected: FAIL — `Cannot find module './vigilCertColumns'`

- [ ] **Step 3: Write the implementation**

Create `dashboard/src/pages/vigilCertColumns.tsx`:

```tsx
// src/pages/vigilCertColumns.tsx
import React from 'react';
import { StatusBadge, certTone } from '../components/StatusBadge';
import { visibleColumns, type ColumnDef } from '../lib/columns';
import type { FlockCert } from '../types';

export type VigilCertColumnKey = 'certName' | 'corgi' | 'domain' | 'daysLeft' | 'status';
export type VigilCertRow = { corgi: string; cert: FlockCert; daysLeft: number };
export type VigilCertColumn = ColumnDef<VigilCertColumnKey, VigilCertRow>;

export const VIGIL_CERT_COLUMNS: VigilCertColumn[] = [
  {
    key: 'certName', header: 'Cert Name', pinned: true, sortable: true,
    sortValue: (r) => r.cert.name,
    render: (r) => <td className="fw-500">{r.cert.name}</td>,
  },
  {
    key: 'corgi', header: 'Corgi', sortable: true,
    sortValue: (r) => r.corgi,
    render: (r) => <td className="text-muted">{r.corgi}</td>,
  },
  {
    key: 'domain', header: 'Domain', sortable: true,
    sortValue: (r) => r.cert.sanNames[0] ?? '',
    render: (r) => <td className="text-muted">{r.cert.sanNames[0] ?? '—'}</td>,
  },
  {
    key: 'daysLeft', header: 'Days Left', sortable: true,
    sortValue: (r) => r.daysLeft,
    render: (r) => {
      const tone = certTone(r.cert.status, r.daysLeft);
      const cls = tone === 'green' ? 'text-green' : tone === 'yellow' ? 'text-yellow' : 'text-red';
      return <td className={cls}>{r.daysLeft > 0 && r.daysLeft < 999 ? r.daysLeft : '—'}</td>;
    },
  },
  {
    key: 'status', header: 'Status', sortable: true,
    sortValue: (r) => r.cert.status,
    render: (r) => {
      const tone = certTone(r.cert.status, r.daysLeft);
      const label = tone === 'yellow' ? `Expiring ${r.daysLeft}d` : tone === 'red' ? 'Error' : 'Valid';
      return <td><StatusBadge label={label} tone={tone} /></td>;
    },
  },
];

export const DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS: VigilCertColumnKey[] = ['certName', 'corgi', 'domain', 'daysLeft', 'status'];

export function visibleVigilCertColumns(visible: ReadonlySet<VigilCertColumnKey>): VigilCertColumn[] {
  return visibleColumns(VIGIL_CERT_COLUMNS, visible);
}
```

Note: the `r.daysLeft > 0 && r.daysLeft < 999` guard preserves the existing `999`-as-"no expiry data" sentinel from `VigilCA.tsx`'s `daysUntil()` helper — do not simplify this to just `> 0`, that would display `999` for certs with no `validTo`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd dashboard && npx vitest run src/pages/vigilCertColumns.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Full verification**

Run: `cd dashboard && npm run typecheck && npm test`
Expected: both succeed

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/pages/vigilCertColumns.tsx dashboard/src/pages/vigilCertColumns.test.ts
git commit -m "feat(dashboard): add Vigil-issued-certs column registry

Cert Name/Corgi/Domain/Days Left/Status columns matching VigilCA.tsx's
existing derived-row shape and sort comparisons. Toggles only the
fields already rendered today — raw ledger fields (serial number,
issued-at, revoked) are explicitly deferred per the design spec."
```

---

### Task 9: VigilCA.tsx table retrofit

**Files:**
- Modify: `dashboard/src/pages/VigilCA.tsx`

**Interfaces:**
- Consumes: `VIGIL_CERT_COLUMNS`, `DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS`, `VigilCertColumnKey` from `./vigilCertColumns` (Task 8); `useColumnVisibility` from `../hooks/useColumnVisibility`; `ColumnMenu` from `../components/ColumnMenu` (Task 2).

- [ ] **Step 1: Add imports, hook, and remove the duplicate SortKey union**

Add to the imports:

```tsx
import { useColumnVisibility } from '../hooks/useColumnVisibility';
import { ColumnMenu } from '../components/ColumnMenu';
import {
  VIGIL_CERT_COLUMNS,
  DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS,
  visibleVigilCertColumns,
  type VigilCertColumnKey,
} from './vigilCertColumns';
```

Replace `type SortKey = 'certName' | 'corgi' | 'domain' | 'daysLeft' | 'status';` with:

```tsx
type SortKey = VigilCertColumnKey;
```

Inside the component, add:

```tsx
const { visible: visibleVigilColumnKeys, toggle: toggleVigilColumn } =
  useColumnVisibility<VigilCertColumnKey>('credo.columns.vigil.issuedCerts', DEFAULT_VISIBLE_VIGIL_CERT_COLUMNS);
```

- [ ] **Step 2: Replace the sort switch**

Replace:

```tsx
const sortedVigilFlockCerts = [...vigilFlockCerts].sort((a, b) => {
  let cmp = 0;
  switch (sort.key) {
    case 'certName': cmp = a.cert.name.localeCompare(b.cert.name); break;
    case 'corgi': cmp = a.corgi.localeCompare(b.corgi); break;
    case 'domain': cmp = (a.cert.sanNames[0] ?? '').localeCompare(b.cert.sanNames[0] ?? ''); break;
    case 'daysLeft': cmp = a.daysLeft - b.daysLeft; break;
    case 'status': cmp = a.cert.status.localeCompare(b.cert.status); break;
  }
  return sort.dir === 'asc' ? cmp : -cmp;
});
```

with:

```tsx
const vigilColumnByKey = new Map(VIGIL_CERT_COLUMNS.map((c) => [c.key, c]));

const sortedVigilFlockCerts = [...vigilFlockCerts].sort((a, b) => {
  const sortValue = vigilColumnByKey.get(sort.key)?.sortValue;
  if (!sortValue) return 0;
  const av = sortValue(a);
  const bv = sortValue(b);
  const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
  return sort.dir === 'asc' ? cmp : -cmp;
});
```

Add near the other derived values (e.g. right after `sortedVigilFlockCerts`):

```tsx
const visibleVigilCols = visibleVigilCertColumns(visibleVigilColumnKeys);
```

- [ ] **Step 3: Replace the card-header and table JSX**

Update the card-header:

```tsx
<div className="card-header">
  <span className="card-title">Vigil-Issued Certificates</span>
  <span className="card-subtitle">{vigilFlockCerts.length} active in fleet</span>
  <ColumnMenu columns={VIGIL_CERT_COLUMNS} visible={visibleVigilColumnKeys} onToggle={toggleVigilColumn} />
</div>
```

Update the `<thead>`:

```tsx
<thead>
  <tr>
    {visibleVigilCols.map((col) => (
      <th key={col.key} className="th-sort" onClick={() => toggleSort(col.key)}>
        {col.header} <span>{sortIndicator(sort.key === col.key, sort.dir)}</span>
      </th>
    ))}
  </tr>
</thead>
```

Update the empty-state `colSpan` from `5` to `visibleVigilCols.length`, and replace the row cells:

```tsx
{sortedVigilFlockCerts.map(({ corgi, cert, daysLeft }) => (
  <tr key={`${corgi}:${cert.name}`}>
    {visibleVigilCols.map((col) => (
      <React.Fragment key={col.key}>{col.render({ corgi, cert, daysLeft })}</React.Fragment>
    ))}
  </tr>
))}
```

(The `tone`/`label` locals computed in the old row callback are no longer needed here — each column's `render` recomputes what it needs internally.)

- [ ] **Step 4: Full verification**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: all succeed

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/pages/VigilCA.tsx
git commit -m "feat(dashboard): configurable columns for Vigil-Issued Certificates table

Same Columns ⚙ control as the other four tables. Toggles only the
currently-rendered fields; wiring in the raw Vigil ledger
(serial number, issued-at, revoked) is deferred per the design spec."
```

---

### Task 10: Final end-to-end verification

**Files:** none (verification only)

- [ ] **Step 1: Full workspace check**

Run: `cd dashboard && npm run typecheck && npm test && npm run build`
Expected: 0 type errors, all tests passing (should now include the 4 new `*.test.ts` files from Tasks 1/3/6/8 plus the untouched Task-1-era tests), build succeeds.

- [ ] **Step 2: Confirm no stray debug code**

Run: `git diff main --stat` (or `git log --stat` for the tasks just committed) and skim each touched file's diff for leftover `console.log`s or commented-out old code blocks. Remove any found, re-commit as a fixup on the relevant task's commit only if something slipped through — otherwise this step is a no-op.

- [ ] **Step 3: Manual QA note**

There is no local `dashboard.config.json` and the credo services run remotely (per this repo's known deployment setup), so full browser click-through against live data should happen in the deployed/remote environment: toggle each table's Columns menu, reload to confirm persistence, confirm Overview's Corgi Fleet and Corgis' outer list maintain independent toggle state, confirm empty-state rows and the Corgis inner-table `colSpan` still render correctly with fewer/more columns visible.
