// Small hand-written SVG charts: sparkline, bar chart, donut. They are
// decorative summaries next to the numbers they show, so each carries an
// aria-label with the underlying figures.

export function Sparkline({
  values,
  color = '#2563eb',
  width = 96,
  height = 28,
}: {
  values: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  if (values.length < 2) return <svg width={width} height={height} aria-hidden="true" />;
  const max = Math.max(1, ...values);
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - 2 - (v / max) * (height - 4)] as const);
  const line = pts.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const area = `${line} L${width},${height} L0,${height} Z`;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`trend: ${values.join(', ')}`}>
      <path d={area} fill={color} opacity={0.1} />
      <path d={line} fill="none" stroke={color} strokeWidth={1.6} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export interface Bar {
  value: number;
  color: string;
  label: string;
}

/** Vertical bars, e.g. actions per hour. Labels are shown every `labelEvery` bars. */
export function BarChart({ bars, height = 120, labelEvery = 6 }: { bars: Bar[]; height?: number; labelEvery?: number }) {
  const max = Math.max(1, ...bars.map((b) => b.value));
  const w = 600;
  const chartH = height - 18;
  const slot = bars.length ? w / bars.length : w;
  const bw = Math.max(2, slot * 0.68);
  return (
    <svg
      width="100%"
      height={height}
      viewBox={`0 0 ${w} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={bars.map((b) => `${b.label}: ${b.value}`).join('; ')}
    >
      <line x1={0} x2={w} y1={chartH} y2={chartH} stroke="#e6e9f0" />
      {bars.map((b, i) => {
        const h = b.value === 0 ? 0 : Math.max(2, (b.value / max) * (chartH - 6));
        const x = i * slot + (slot - bw) / 2;
        return (
          <g key={i}>
            <rect x={x} y={chartH - h} width={bw} height={h} rx={2} fill={b.color}>
              <title>{`${b.label}: ${b.value}`}</title>
            </rect>
            {i % labelEvery === 0 && (
              <text x={x + bw / 2} y={height - 4} fontSize={10} textAnchor="middle" fill="#8a94a6">
                {b.label}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

export interface Slice {
  label: string;
  value: number;
  color: string;
}

/** Donut with the total in the middle. */
export function Donut({ slices, size = 132, thickness = 18, center }: { slices: Slice[]; size?: number; thickness?: number; center?: string }) {
  const total = slices.reduce((a, s) => a + s.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={slices.map((s) => `${s.label}: ${s.value}`).join('; ') || 'no data'}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#eef1f6" strokeWidth={thickness} />
      {total > 0 &&
        slices
          .filter((s) => s.value > 0)
          .map((s) => {
            const len = (s.value / total) * c;
            const el = (
              <circle
                key={s.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={thickness}
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
              >
                <title>{`${s.label}: ${s.value}`}</title>
              </circle>
            );
            offset += len;
            return el;
          })}
      <text x="50%" y="48%" textAnchor="middle" fontSize={20} fontWeight={700} fill="#0f172a">
        {center ?? total.toLocaleString()}
      </text>
      <text x="50%" y="62%" textAnchor="middle" fontSize={10.5} fill="#8a94a6">
        actions
      </text>
    </svg>
  );
}

/** A categorical palette for verbs in the action-mix donut. */
export const MIX_COLORS = ['#2563eb', '#16a34a', '#f59e0b', '#7c3aed', '#0891b2', '#db2777', '#64748b', '#ea580c', '#84cc16', '#dc2626'];
