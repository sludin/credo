// src/components/StatusBadge.tsx
import React from 'react';

type Tone = 'green' | 'yellow' | 'red' | 'blue' | 'muted';

type Props = {
  label: string;
  tone: Tone;
  spinning?: boolean;
};

const toneStyles: Record<Tone, React.CSSProperties> = {
  green:  { background: 'rgba(34,197,94,0.12)',  color: 'var(--green)' },
  yellow: { background: 'rgba(245,158,11,0.12)', color: 'var(--yellow)' },
  red:    { background: 'rgba(239,68,68,0.12)',  color: 'var(--red)' },
  blue:   { background: 'rgba(59,130,246,0.12)', color: 'var(--blue)' },
  muted:  { background: 'rgba(148,163,184,0.1)', color: 'var(--muted)' },
};

export function certTone(status: string, daysLeft?: number): Tone {
  if (status === 'not-ok') return 'red';
  if (daysLeft !== undefined && daysLeft <= 14) return 'yellow';
  if (status === 'ok') return 'green';
  return 'muted';
}

export function serviceTone(status: string): Tone {
  if (status === 'healthy' || status === 'reachable' || status === 'ok') return 'green';
  if (status === 'unreachable' || status === 'not-ok' || status === 'error') return 'red';
  return 'muted';
}

export function StatusBadge({ label, tone, spinning }: Props): React.ReactElement {
  const style: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', gap: 4,
    padding: '2px 8px', borderRadius: 99,
    fontSize: 11, fontWeight: 500,
    ...toneStyles[tone],
  };
  const dotStyle: React.CSSProperties = spinning
    ? {
        display: 'inline-block',
        width: 8, height: 8,
        border: '1.5px solid currentColor',
        borderTopColor: 'transparent',
        borderRadius: '50%',
        animation: 'spin 0.7s linear infinite',
        flexShrink: 0,
      }
    : {
        width: 6, height: 6, borderRadius: '50%', background: 'currentColor', flexShrink: 0,
      };
  return (
    <span style={style}>
      <span style={dotStyle} />
      {label}
    </span>
  );
}
