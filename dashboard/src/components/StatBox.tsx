// src/components/StatBox.tsx
import React from 'react';

type Props = {
  value: string | number;
  label: string;
  tone?: 'green' | 'yellow' | 'red' | 'blue' | 'default';
};

const toneColor: Record<NonNullable<Props['tone']>, string> = {
  green: 'var(--green)',
  yellow: 'var(--yellow)',
  red: 'var(--red)',
  blue: 'var(--blue)',
  default: 'var(--text)',
};

export function StatBox({ value, label, tone = 'default' }: Props): React.ReactElement {
  return (
    <div style={{
      background: 'var(--surface2)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '10px 12px',
      display: 'flex', flexDirection: 'column', gap: 3,
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, lineHeight: 1, color: toneColor[tone] }}>
        {value}
      </div>
      <div style={{ fontSize: 11, color: 'var(--muted)' }}>{label}</div>
    </div>
  );
}
