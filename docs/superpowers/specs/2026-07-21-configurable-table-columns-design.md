---
date: 2026-07-21
topic: configurable-table-columns
status: approved
---

# Design: Configurable Columns — Remaining Dashboard Tables

## Context

The Overview page's "Certificate Health" table already got a configurable-columns
treatment: a `useColumnVisibility` hook (localStorage-backed), a per-table column
registry (`certHealthColumns.tsx`), and a "Columns ⚙" trigger reusing the existing
`.action-menu` dropdown from `theme.css`. The user wants the same control on four
more tables across the dashboard, plus a decision on whether it applies to the
cert detail structured output.

## Scope

**In scope:**
- Overview page → Corgi Fleet table
- Corgis page → outer corgi list table
- Certificates page → main cert list table
- VigilCA page → Vigil-Issued Certificates table

**Explicitly out of scope (deferred, decided during design Q&A):**
- Corgis page's inner per-corgi cert table (nested inside each expandable row) —
  stays static; no header slot exists for a trigger and the user opted to leave it.
- The CA list page (`ShepherdCAs.tsx`) — left alone entirely; low-traffic, short
  list, not worth the added surface area right now (it also has no sorting today,
  which was explicitly declined as an add-on).
- CertViewer's structured section/field output (Tools → Cert Viewer) — this is a
  different UI shape (hierarchical sections, not tabular). If tackled later, the
  right analog is **collapsible sections** (a `useSectionVisibility`-style hook),
  not column toggling. Deferred to a future spec.
- The raw Vigil ledger fields (`serialNumber`, `issuedAt`, `revoked`) — the
  Vigil-Issued Certificates table doesn't currently join this data in; wiring it up
  is a data-model change, not a UI toggle. Deferred.

## Architecture

Three approaches were considered:

1. **Copy the exact per-table pattern** into each new table as-is (what batch one
   did). Simple, but repeats the same ~15-line dropdown JSX and filter function
   four more times.
2. **Generic reusable table/column framework.** Reduces duplication further but
   reworks every page's JSX around a new abstraction — more invasive than what
   was asked, and explicitly ruled out when the first table was built.
3. **Middle ground (chosen):** keep each table's column registry and sort state
   independent (as before), but extract the two pieces that are now duplicated
   byte-for-byte across five tables — the visibility-filtering logic and the
   dropdown UI — into small shared modules.

**New shared modules:**
- `dashboard/src/lib/columns.ts` — generic `ColumnDef<K extends string, Row>` type
  and `visibleColumns(all, visible)` filter (pinned columns always kept), lifted
  out of `certHealthColumns.tsx`.
- `dashboard/src/components/ColumnMenu.tsx` — `<ColumnMenu columns={} visible={}
  onToggle={} />`, replacing the hand-rolled `<details className="action-menu">`
  dropdown currently inline in `Overview.tsx`.

`useColumnVisibility` (localStorage-backed hook) is already generic and needs no
changes.

**Retrofit:** `certHealthColumns.tsx` and `Overview.tsx`'s cert table switch to
the shared `ColumnDef`/`visibleColumns`/`ColumnMenu` instead of their local
copies. Behavior is unchanged — `certHealthColumns.test.ts` should keep passing
without modification.

## Per-table plan

| Table | Registry file | Row shape | Pinned column | Storage key | Trigger location |
|---|---|---|---|---|---|
| Overview → Corgi Fleet | `corgiColumns.tsx` (shared base) + one Overview-only "Services" column | `CorgiState` | Name | `credo.columns.overview.corgiFleet` | existing `card-header` |
| Corgis → outer corgi list | `corgiColumns.tsx` (shared base, as-is) | `CorgiState` | Name | `credo.columns.corgis.corgiList` | existing `card-header` |
| Certificates → main list | `certificateListColumns.tsx` | `UnifiedCertRow` | Name/domain | `credo.columns.certificates.list` | existing `.filter-bar` |
| VigilCA → issued certs | `vigilCertColumns.tsx` | `{corgi, cert, daysLeft}` | Cert Name | `credo.columns.vigil.issuedCerts` | existing `card-header` |

**Shared corgi columns:** Overview's Corgi Fleet and Corgis' outer list render
identical data (`CorgiState`) with four identical columns (Name, Host, Status,
Certs, Last Seen) plus Last-Seen formatting — only Overview additionally shows a
"Services" column (global Shepherd API health, not per-row). Rather than
duplicate five column definitions, `corgiColumns.tsx` exports the shared base and
Overview appends its own extra column locally. Visibility **state** stays
independent per page (separate storage keys), per the design Q&A — only the
column *definitions* are shared, not the toggle state.

**Certificates and VigilCA columns:** built fresh per-table (no cross-page
sharing), matching each page's existing `SortKey` type and cell-rendering logic
one-for-one.

## Defaults

Every column in every table defaults to **visible**. Unlike the cert-health
table's Monitor Status precedent, nothing new is being surfaced here — this
batch only makes existing columns hideable, so day-one behavior is unchanged
until a user opens the Columns menu.

## Testing

Each new/retrofitted registry gets the same `visibleColumns`-focused unit tests
as `certHealthColumns.test.ts` (pinned column always retained, default-visible
set matches the current column list, unknown/stale keys ignored gracefully).
`dashboard/src/lib/columns.ts` gets its own direct test coverage since it's now
shared across five tables. No new React-rendering tests are added — the
codebase has no component-rendering test setup (no React Testing Library), so
this follows the existing `*.testable.ts`-style convention of testing pure
logic only.

## Verification

- `cd dashboard && npm test` — all new/retrofitted unit tests passing, existing
  suite unaffected.
- `cd dashboard && npm run typecheck` — required by the repo's pre-commit hook
  for any `dashboard/` change.
- `cd dashboard && npm run build` — production bundle succeeds.
- Manual QA per table (once buildable against a real or remote backend): toggle
  each column, reload to confirm persistence, confirm empty-state colSpan still
  matches visible column count, confirm sorting still works, confirm the
  Overview/Corgis independent-state behavior (toggling one doesn't affect the
  other).
