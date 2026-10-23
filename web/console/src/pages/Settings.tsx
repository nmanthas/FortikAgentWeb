// Settings → Agent types (docs/PHASE3_DESIGN.md §2.8): the expected
// population per agent type. 0 means "no limit" for the rate fields and
// "not set" for the counts.

import { useState } from 'react';
import { listAgentTypes, putAgentType } from '../api/endpoints';
import type { AgentType } from '../api/types';
import { useMe } from '../App';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, ReasonDialog } from '../components/ui';
import { useLiveRefresh } from '../lib/live';
import { hasRole } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

type NumField = 'expectedMaxInstances' | 'maxAgents' | 'spawnRatePerMin' | 'actionRatePerMin';
const FIELDS: { key: NumField; label: string; help: string }[] = [
  { key: 'expectedMaxInstances', label: 'Expected max instances', help: 'Live copies across all agents of the type (POL-702)' },
  { key: 'maxAgents', label: 'Max agents', help: 'Registered agents of the type' },
  { key: 'spawnRatePerMin', label: 'Spawns / min', help: 'Static ceiling; 0 = baseline only (POL-703)' },
  { key: 'actionRatePerMin', label: 'Actions / min per agent', help: '0 = unlimited (POL-704)' },
];
/** Mirrors internal/population typePattern and maxLimit. */
const typePattern = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}$/;
const MAX_LIMIT = 1_000_000;

export function validAgentType(t: AgentType): string | null {
  if (!typePattern.test(t.type)) return 'Type names start with a letter or digit and use letters, digits and _ . : @ - (up to 64).';
  for (const f of FIELDS) {
    const v = t[f.key];
    if (!Number.isInteger(v) || v < 0 || v > MAX_LIMIT) return `${f.label} must be a whole number from 0 to ${MAX_LIMIT.toLocaleString('en-US')}.`;
  }
  return null;
}

type Row = { t: AgentType; isNew: boolean; idx: number };

export function SettingsPage() {
  return <AgentTypesEditor />;
}

function AgentTypesEditor() {
  const me = useMe();
  const toast = useToast();
  const types = useAsync<AgentType[]>((s) => listAgentTypes(s), []);
  useLiveRefresh((e) => e.eventType === 'agent_type.changed', types.reload, 800);
  const canEdit = hasRole(me, 'security');
  const [edits, setEdits] = useState<Record<string, AgentType>>({});
  const [added, setAdded] = useState<AgentType[]>([]);
  const [error, setError] = useState<unknown>(null);

  const rows: Row[] = [
    ...(types.data ?? []).map((t, idx) => ({ t: edits[t.type] ?? t, isNew: false, idx })),
    ...added.map((t, idx) => ({ t, isNew: true, idx })),
  ];

  const setRow = (r: Row, next: AgentType) => {
    if (r.isNew) setAdded((a) => a.map((x, i) => (i === r.idx ? next : x)));
    else setEdits((e) => ({ ...e, [r.t.type]: next }));
  };

  const [saving, setSaving] = useState<Row | null>(null);

  const discard = (r: Row) => {
    if (r.isNew) setAdded((a) => a.filter((_, i) => i !== r.idx));
    else
      setEdits((e) => {
        const n = { ...e };
        delete n[r.t.type];
        return n;
      });
  };

  const startSave = (r: Row) => {
    const problem = validAgentType(r.t);
    if (problem) {
      setError(new Error(problem));
      return;
    }
    if (r.isNew && (types.data ?? []).some((t) => t.type === r.t.type)) {
      setError(new Error(`Agent type ${r.t.type} already exists: edit its row instead.`));
      return;
    }
    setError(null);
    setSaving(r);
  };

  const save = async (r: Row, reason: string) => {
    await putAgentType(r.t, reason);
    toast({ tone: 'green', title: `Agent type ${r.t.type} saved` });
    if (r.isNew) setAdded((a) => a.filter((_, i) => i !== r.idx));
    else
      setEdits((e) => {
        const n = { ...e };
        delete n[r.t.type];
        return n;
      });
    types.reload();
  };

  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h2>Agent types</h2>
          <div className="sub">Expected population and rate limits per agent type. Spikes above these are throttled and raise alerts.</div>
        </div>
        <button className="btn" disabled={!canEdit} onClick={() => setAdded((a) => [...a, { type: '', expectedMaxInstances: 0, maxAgents: 0, spawnRatePerMin: 0, actionRatePerMin: 0 }])}>
          Add type
        </button>
      </div>
      {!canEdit && <div className="alert info" style={{ margin: '0 20px 12px' }}>Editing agent types requires the security role.</div>}
      <div style={{ padding: '0 20px' }}>
        <ErrorBox error={error} />
      </div>
      {types.error && <ErrorBox error={types.error} onRetry={types.reload} />}
      {types.loading && !types.data && <Loading />}
      {types.data && rows.length === 0 && <div className="empty">No agent types defined yet.</div>}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Type</th>
                {FIELDS.map((f) => (
                  <th key={f.key} title={f.help}>
                    {f.label}
                  </th>
                ))}
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const dirty = r.isNew || edits[r.t.type] !== undefined;
                const name = r.t.type || 'new type';
                return (
                  <tr key={`${r.isNew ? 'new' : 'old'}-${r.idx}`}>
                    <td>
                      {r.isNew ? (
                        <input className="input" aria-label="Type name" value={r.t.type} disabled={!canEdit} onChange={(e) => setRow(r, { ...r.t, type: e.target.value })} />
                      ) : (
                        <code>{r.t.type}</code>
                      )}
                    </td>
                    {FIELDS.map((f) => (
                      <td key={f.key}>
                        <input
                          className="input"
                          type="number"
                          min={0}
                          step={1}
                          aria-label={`${f.label} for ${name}`}
                          disabled={!canEdit}
                          value={r.t[f.key]}
                          onChange={(e) => setRow(r, { ...r.t, [f.key]: e.target.value === '' ? 0 : Number(e.target.value) })}
                        />
                      </td>
                    ))}
                    <td>
                      <div className="btn-row">
                        <button className="btn small primary" disabled={!canEdit || !dirty} onClick={() => startSave(r)} aria-label={`Save ${name}`}>
                          Save
                        </button>
                        {dirty && (
                          <button className="btn small" onClick={() => discard(r)} aria-label={`Discard changes to ${name}`}>
                            Discard
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {saving && (
        <ReasonDialog
          title={`Save agent type ${saving.t.type}?`}
          description="New limits apply to the next decisions for every agent of this type."
          confirmLabel="Save"
          onConfirm={(reason) => save(saving, reason)}
          onClose={() => setSaving(null)}
        />
      )}
    </div>
  );
}
