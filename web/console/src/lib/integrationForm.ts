// Form model for the integration Configure drawer, rendered from
// GET /v1/integrations/schema (docs/PHASE2_DESIGN.md §7).
//
// Secret fields are write-only. The form never holds a stored secret value:
// a stored secret shows as "set", and the payload carries a secret only when
// the user typed a new one ("replace"), or null when they removed an optional
// one. An empty string is never sent (the server rejects it).

import type { Integration, IntegrationSchema, SchemaField } from '../api/types';

export type SecretState = { mode: 'keep' } | { mode: 'replace'; value: string } | { mode: 'remove' };

export interface IntegrationFormState {
  values: Record<string, string | boolean>;
  secrets: Record<string, SecretState>;
}

/** Postgres upstream names (the part after "postgres:"); matches the server. */
export const POSTGRES_NAME = /^[a-z][a-z0-9_]{0,62}$/;

export const SYSTEM_ORDER = ['google_workspace', 'github', 'aws', 'postgres', 'memory', 'temporal', 'celery', 'queue_webhook'];

/** Instance names of multi-instance systems ("postgres:<name>", "memory:<name>"); same rule as the server. */
export const INSTANCE_NAME = POSTGRES_NAME;

/** Display name of one instance of a multi-instance system. */
export const MULTI_TITLE: Record<string, { card: string; noun: string; placeholder: string; help: string }> = {
  postgres: {
    card: 'PostgreSQL',
    noun: 'Postgres upstream',
    placeholder: 'acme_staging',
    help: "Agents connect to Fortik's pgproxy using this name as the database name, and access profiles grant it by name.",
  },
  memory: {
    card: 'Memory store',
    noun: 'memory store',
    placeholder: 'support_memory',
    help: 'Agents reach this vector store through /gw/memory/<name>/... and memory MCP tools; every read and write is decided.',
  },
};

/** The display title for an integration key: "PostgreSQL · acme_prod", or the schema title for single systems. */
export function integrationTitle(schema: IntegrationSchema, key: string): string {
  if (!schema.multi) return schema.title;
  const name = key.startsWith(`${schema.system}:`) ? key.slice(schema.system.length + 1) : key;
  return `${MULTI_TITLE[schema.system]?.card ?? schema.title} · ${name}`;
}

function asText(v: unknown): string {
  if (v === undefined || v === null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

/** Initial form state from the schema and the stored integration (if any). */
export function initialForm(schema: IntegrationSchema, current: Integration | undefined): IntegrationFormState {
  const values: Record<string, string | boolean> = {};
  const secrets: Record<string, SecretState> = {};
  const cfg = current?.config ?? {};
  for (const f of schema.fields) {
    if (f.secret) {
      secrets[f.key] = current?.secrets[f.key]?.set ? { mode: 'keep' } : { mode: 'replace', value: '' };
      continue;
    }
    // Stored config wins; otherwise the schema default (the server stores defaults too).
    const v = cfg[f.key] !== undefined && cfg[f.key] !== null ? cfg[f.key] : f.default;
    switch (f.type) {
      case 'bool':
        values[f.key] = v === true;
        break;
      case 'list':
        values[f.key] = Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').join('\n') : asText(v);
        break;
      default:
        values[f.key] = asText(v);
    }
  }
  return { values, secrets };
}

export function isSecretSet(current: Integration | undefined, key: string): boolean {
  return current?.secrets[key]?.set === true;
}

/** Client-side checks for quick feedback (the server validates everything again). */
export function formProblems(schema: IntegrationSchema, st: IntegrationFormState, current: Integration | undefined): string[] {
  const out: string[] = [];
  for (const f of schema.fields) {
    if (f.secret) {
      const s = st.secrets[f.key] ?? { mode: 'keep' };
      const willBeSet = s.mode === 'keep' ? isSecretSet(current, f.key) : s.mode === 'replace' ? s.value.trim() !== '' : false;
      if (f.required && !willBeSet) out.push(`${f.label} is required.`);
      continue;
    }
    const v = st.values[f.key];
    if (f.type === 'bool') continue;
    const text = typeof v === 'string' ? v.trim() : '';
    if (f.required && text === '') out.push(`${f.label} is required.`);
    if (f.type === 'number' && text !== '' && !/^-?\d+$/.test(text)) out.push(`${f.label} must be a whole number.`);
    if (f.type === 'select' && text !== '' && f.options && !f.options.includes(text)) out.push(`${f.label} must be one of ${f.options.join(', ')}.`);
  }
  return out;
}

function configValue(f: SchemaField, v: string | boolean | undefined): unknown {
  if (f.type === 'bool') return v === true;
  const text = typeof v === 'string' ? v.trim() : '';
  if (f.type === 'list') {
    return [
      ...new Set(
        text
          .split(/[\n,]/)
          .map((x) => x.trim())
          .filter(Boolean),
      ),
    ];
  }
  if (text === '') return undefined;
  if (f.type === 'number') return Number(text);
  return text;
}

/** Builds the PUT /v1/integrations/{key} body {config, secrets}. */
export function buildPayload(schema: IntegrationSchema, st: IntegrationFormState): { config: Record<string, unknown>; secrets: Record<string, string | null> } {
  const config: Record<string, unknown> = {};
  const secrets: Record<string, string | null> = {};
  for (const f of schema.fields) {
    if (f.secret) {
      const s = st.secrets[f.key];
      if (!s || s.mode === 'keep') continue;
      if (s.mode === 'remove') {
        if (!f.required) secrets[f.key] = null;
        continue;
      }
      // Secrets are sent exactly as typed (PEM and JSON keys are whitespace
      // sensitive at the edges only by accident; trimming would be harmless
      // but we only drop a value that is entirely blank).
      if (s.value.trim() !== '') secrets[f.key] = s.value;
      continue;
    }
    const v = configValue(f, st.values[f.key]);
    if (v !== undefined) config[f.key] = v;
  }
  return { config, secrets };
}

/** Human description of what each integration is for (card text). */
export const SYSTEM_BLURB: Record<string, string> = {
  google_workspace:
    'Lets Fortik act on Gmail and Drive for your agents through a service account with domain-wide delegation. Tokens never leave Fortik.',
  github: 'A GitHub App that Fortik uses to mint short-lived installation tokens narrowed to each agent’s repositories and permissions.',
  aws: 'Fortik assumes one IAM role for agents and hands out 15-minute sessions allowing exactly the requested action on the requested resource.',
  postgres: 'A database agents reach through pgproxy. Fortik creates a login role per agent and rotates its password every session.',
  memory:
    'A Postgres + pgvector store for agents’ long-term memory. Writes are staged before promotion, snapshots allow rollback, and Fortik keeps only pointers.',
  temporal: 'Pause, resume or cancel an agent’s workflows (tagged with the FortikAgentId search attribute) when it is suspended or killed.',
  celery: 'Hold, release or revoke an agent’s Celery tasks (header fortik_agent_id) on the Redis broker when it is suspended or killed.',
  queue_webhook: 'Your own job system: Fortik POSTs signed pause/resume/cancel requests for an agent and treats only a 2xx answer as done.',
};

export const SYSTEM_STEPS: Record<string, string[]> = {
  google_workspace: [
    'Create a Google Cloud service account and download a JSON key.',
    'In the Admin console, authorise its Client ID for domain-wide delegation with the Gmail and Drive scopes.',
    'Enter your primary domain and a test user, paste the JSON key, save, then Test connection.',
  ],
  github: [
    'Create a GitHub App (Settings > Developer settings > GitHub Apps) with the repository permissions your agents need.',
    'Install it on your organisation and note the installation ID from the URL.',
    'Generate a private key, paste it with the App ID and installation ID, save, then Test connection.',
  ],
  aws: [
    'Create an IAM role for agents whose trust policy allows Fortik’s IAM user to assume it (and set source identity).',
    'Create an IAM user for Fortik allowed only sts:AssumeRole on that role and iam:PutRolePolicy on it.',
    'Enter the region, role ARN and the user’s access key, save, then Test connection.',
  ],
  memory: [
    'Create a Postgres database with the pgvector extension (CREATE EXTENSION vector).',
    'Create an admin role Fortik can use to manage the fortik_memory schema.',
    'Enter the connection details, paste the admin credentials, save, then Test connection.',
  ],
  temporal: [
    'Register the FortikAgentId search attribute (Keyword) in your namespace and set it on agents’ workflows.',
    'Enter the frontend host:port and namespace (plus TLS or an API key for Temporal Cloud).',
    'Save, then Test connection.',
  ],
  celery: [
    'Make your producers set the fortik_agent_id header on every task they enqueue for an agent.',
    'Enter the Redis broker URL (stored as a secret) and the queue names to manage.',
    'Save, then Test connection.',
  ],
  queue_webhook: [
    'Expose an HTTPS endpoint that pauses, resumes or cancels an agent’s jobs and verifies X-Fortik-Signature (HMAC-SHA256).',
    'Enter the URL and a shared secret.',
    'Save, then Test connection.',
  ],
  postgres: [
    'Create two NOLOGIN group roles holding read and read/write grants.',
    'Create an admin role with CREATEROLE (not superuser) that can grant them.',
    'Enter the connection details and roles, save, then Test connection.',
  ],
};
