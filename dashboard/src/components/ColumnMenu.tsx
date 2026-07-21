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
