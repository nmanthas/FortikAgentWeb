import type { Slice } from '../components/Charts';

export function DonutLegend({ slices }: { slices: Slice[] }) {
  if (slices.length === 0) return <div className="muted small">No actions in the last 24 hours.</div>;
  return (
    <div className="stat-list grow">
      {slices.map((s) => (
        <div key={s.label} className="stat-row">
          <span className="legend-dot" style={{ background: s.color }} />
          {s.label}
          <span className="n">{s.value}</span>
        </div>
      ))}
    </div>
  );
}
