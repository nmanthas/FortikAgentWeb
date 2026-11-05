// Access-profile form models (docs/PHASE2_DESIGN.md §5). Each system's
// profile JSON is converted to an editable form model and back. New profiles
// start from the most restrictive values ("none"): granting access is always
// an explicit choice. Client-side checks mirror internal/access/validate.go
// for quick feedback; the server validates again and its errors are shown.

import type { AccessSystem } from '../api/types';

export type Mode = 'none' | 'read_only' | 'read_write';
export type Send = 'none' | 'internal_only' | 'any';
export type Perm = 'none' | 'read' | 'write';

export interface GmailForm {
  send: Send;
  read: boolean;
  maxRecipients: number;
}
export interface DriveForm {
  mode: Mode;
  share: Send;
}
export interface GitHubForm {
  repos: string[];
  contents: Perm;
  pullRequests: Perm;
  issues: Perm;
  metadata: 'none' | 'read';
  allowDirectToken: boolean;
}
export interface AWSForm {
  mode: Mode;
  services: string[];
  deniedActions: string[];
}
export interface PostgresForm {
  upstreams: { name: string; mode: Mode }[];
}

/** a2a: agents this agent may delegate to (["*"] = any) and the deepest chain it may start or extend. */
export interface A2AForm {
  anyAgent: boolean;
  mayDelegateTo: string[];
  maxDepth: number;
}
export type External = 'none' | 'allowlist' | 'any';
export interface HTTPForm {
  external: External;
  allowedDomains: string[];
}
/** mcp: server name -> allowed tools (["*"] = every tool). */
export interface MCPForm {
  servers: { name: string; allTools: boolean; tools: string[] }[];
}

/**
 * netsuite: every NetSuite transport (the REST gateway, the QuickStart and
 * AI Connector MCP endpoints). record_types ["*"] = every type;
 * quickstart_tools absent = every tool the mode allows; integrations absent
 * = every NetSuite tenant (logical integration ids such as netsuite:acme).
 */
export interface NetSuiteForm {
  mode: Mode;
  allTypes: boolean;
  recordTypes: string[];
  suiteql: boolean;
  allTools: boolean;
  quickstartTools: string[];
  allTenants: boolean;
  tenants: string[];
}

/** A NetSuite logical integration id (same rule as the server). */
export const netsuiteTenantPattern = /^netsuite:[a-z][a-z0-9_]{0,62}$/;

export type FormFor<S extends AccessSystem> = S extends 'gmail'
  ? GmailForm
  : S extends 'drive'
    ? DriveForm
    : S extends 'github'
      ? GitHubForm
      : S extends 'aws'
        ? AWSForm
        : S extends 'a2a'
          ? A2AForm
          : S extends 'http'
            ? HTTPForm
            : S extends 'mcp'
              ? MCPForm
              : S extends 'netsuite'
                ? NetSuiteForm
                : S extends 'salesforce' | 'servicenow' | 'sap'
                  ? SaaSForm
                  : PostgresForm;

/**
 * salesforce / servicenow / sap: one profile for both transports (REST and
 * MCP). objects ["*"] = every object (Salesforce object, ServiceNow table,
 * SAP <SERVICE>/<EntitySet>); integrations and mcp_tools absent = all.
 */
export interface SaaSForm {
  mode: Mode;
  allObjects: boolean;
  objects: string[];
  allTenants: boolean;
  tenants: string[];
  allTools: boolean;
  tools: string[];
}

const isSaaS = (s: AccessSystem) => s === 'salesforce' || s === 'servicenow' || s === 'sap';

export type AnyForm = GmailForm | DriveForm | GitHubForm | AWSForm | PostgresForm | A2AForm | HTTPForm | MCPForm | NetSuiteForm | SaaSForm;

/** Mirrors access.MaxDelegationDepth. */
export const MAX_DELEGATION_DEPTH = 32;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const oneOf = <T extends string>(v: unknown, allowed: readonly T[], d: T): T =>
  typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : d;
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

const MODES = ['none', 'read_only', 'read_write'] as const;
const SENDS = ['none', 'internal_only', 'any'] as const;
const PERMS = ['none', 'read', 'write'] as const;
const EXTERNALS = ['none', 'allowlist', 'any'] as const;

/** Converts profile JSON (or null for "no profile") to a form model. Unknown values fall back to "none". */
export function toForm(system: AccessSystem, profile: unknown): AnyForm {
  const p = isObj(profile) ? profile : {};
  if (isSaaS(system)) {
    const all = (v: unknown) => !Array.isArray(v) || strList(v).includes('*');
    const objs = Array.isArray(p.objects) ? strList(p.objects) : [];
    return {
      mode: oneOf(p.mode, MODES, 'none'),
      allObjects: objs.includes('*'),
      objects: objs.includes('*') ? [] : objs,
      allTenants: all(p.integrations),
      tenants: all(p.integrations) ? [] : strList(p.integrations),
      allTools: all(p.mcp_tools),
      tools: all(p.mcp_tools) ? [] : strList(p.mcp_tools),
    };
  }
  switch (system) {
    case 'gmail':
      return {
        send: oneOf(p.send, SENDS, 'none'),
        read: p.read === true,
        maxRecipients: typeof p.max_recipients === 'number' ? p.max_recipients : 0,
      };
    case 'drive':
      return { mode: oneOf(p.mode, MODES, 'none'), share: oneOf(p.share, SENDS, 'none') };
    case 'github': {
      const perms = isObj(p.permissions) ? p.permissions : {};
      return {
        repos: strList(p.repos),
        contents: oneOf(perms.contents, PERMS, 'none'),
        pullRequests: oneOf(perms.pull_requests, PERMS, 'none'),
        issues: oneOf(perms.issues, PERMS, 'none'),
        metadata: oneOf(perms.metadata, ['none', 'read'] as const, 'none'),
        allowDirectToken: p.allow_direct_token === true,
      };
    }
    case 'aws':
      return { mode: oneOf(p.mode, MODES, 'none'), services: strList(p.services), deniedActions: strList(p.denied_actions) };
    case 'postgres': {
      const ups = isObj(p.upstreams) ? p.upstreams : {};
      return {
        upstreams: Object.entries(ups)
          .map(([name, mode]) => ({ name, mode: oneOf(mode, MODES, 'none') }))
          .sort((a, b) => a.name.localeCompare(b.name)),
      };
    }
    case 'a2a': {
      const to = strList(p.may_delegate_to);
      const anyAgent = to.length === 1 && to[0] === '*';
      return {
        anyAgent,
        mayDelegateTo: anyAgent ? [] : to,
        maxDepth: typeof p.max_depth === 'number' ? p.max_depth : 1,
      };
    }
    case 'http':
      return { external: oneOf(p.external, EXTERNALS, 'none'), allowedDomains: strList(p.allowed_domains) };
    case 'mcp': {
      const servers = isObj(p.servers) ? p.servers : {};
      return {
        servers: Object.entries(servers)
          .map(([name, tools]) => {
            const t = strList(tools);
            const allTools = t.length === 1 && t[0] === '*';
            return { name, allTools, tools: allTools ? [] : t };
          })
          .sort((a, b) => a.name.localeCompare(b.name)),
      };
    }
    case 'netsuite': {
      const types = strList(p.record_types);
      const tools = Array.isArray(p.quickstart_tools) ? strList(p.quickstart_tools) : null;
      const tenants = Array.isArray(p.integrations) ? strList(p.integrations) : null;
      return {
        mode: oneOf(p.mode, MODES, 'none'),
        allTypes: types.length === 1 && types[0] === '*',
        recordTypes: types.length === 1 && types[0] === '*' ? [] : types,
        suiteql: p.suiteql === true,
        allTools: tools === null || (tools.length === 1 && tools[0] === '*'),
        quickstartTools: tools === null || (tools.length === 1 && tools[0] === '*') ? [] : tools,
        allTenants: tenants === null || tenants.includes('*'),
        tenants: tenants === null || tenants.includes('*') ? [] : tenants,
      };
    }
  }
}

/** Converts a form model to the profile JSON the API expects. */
export function fromForm(system: AccessSystem, form: AnyForm): Obj {
  if (isSaaS(system)) {
    const f = form as SaaSForm;
    const out: Obj = { mode: f.mode, objects: f.allObjects ? ['*'] : cleanList(f.objects.map((o) => o.toLowerCase())) };
    if (!f.allTenants) out.integrations = cleanList(f.tenants.map((t) => t.toLowerCase()));
    if (!f.allTools) out.mcp_tools = cleanList(f.tools);
    return out;
  }
  switch (system) {
    case 'gmail': {
      const f = form as GmailForm;
      return { send: f.send, read: f.read, max_recipients: f.maxRecipients };
    }
    case 'drive': {
      const f = form as DriveForm;
      return { mode: f.mode, share: f.share };
    }
    case 'github': {
      const f = form as GitHubForm;
      const permissions: Record<string, string> = {};
      if (f.contents !== 'none') permissions.contents = f.contents;
      if (f.pullRequests !== 'none') permissions.pull_requests = f.pullRequests;
      if (f.issues !== 'none') permissions.issues = f.issues;
      if (f.metadata !== 'none') permissions.metadata = f.metadata;
      return { repos: cleanList(f.repos), permissions, allow_direct_token: f.allowDirectToken };
    }
    case 'aws': {
      const f = form as AWSForm;
      return { mode: f.mode, services: cleanList(f.services), denied_actions: cleanList(f.deniedActions) };
    }
    case 'postgres': {
      const f = form as PostgresForm;
      const upstreams: Record<string, string> = {};
      for (const u of f.upstreams) {
        const n = u.name.trim();
        if (n !== '') upstreams[n] = u.mode;
      }
      return { upstreams };
    }
    case 'a2a': {
      const f = form as A2AForm;
      return { may_delegate_to: f.anyAgent ? ['*'] : cleanList(f.mayDelegateTo), max_depth: f.maxDepth };
    }
    case 'http': {
      const f = form as HTTPForm;
      return f.external === 'allowlist' ? { external: f.external, allowed_domains: cleanList(f.allowedDomains.map(normDomain)) } : { external: f.external };
    }
    case 'mcp': {
      const f = form as MCPForm;
      const servers: Record<string, string[]> = {};
      for (const sv of f.servers) {
        const n = sv.name.trim();
        if (n !== '') servers[n] = sv.allTools ? ['*'] : cleanList(sv.tools);
      }
      return { servers };
    }
    case 'netsuite': {
      const f = form as NetSuiteForm;
      const out: Obj = { mode: f.mode, record_types: f.allTypes ? ['*'] : cleanList(f.recordTypes.map((t) => t.toLowerCase())), suiteql: f.suiteql };
      if (!f.allTools) out.quickstart_tools = cleanList(f.quickstartTools);
      if (!f.allTenants) out.integrations = cleanList(f.tenants.map((t) => t.toLowerCase()));
      return out;
    }
  }
}

/** Mirrors access.NormalizeDomainPattern: lowercase, no trailing dot. */
const normDomain = (d: string): string => d.trim().toLowerCase().replace(/\.$/, '');

function cleanList(xs: string[]): string[] {
  return [...new Set(xs.map((x) => x.trim()).filter((x) => x !== ''))];
}

const repoPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const awsServicePattern = /^[a-z0-9][a-z0-9-]{0,63}$/;
const awsDeniedPattern = /^(?:\*|[a-z0-9*?][a-z0-9*?-]{0,63}:[a-z0-9*?]{1,128})$/;
const upstreamPattern = /^[A-Za-z_][A-Za-z0-9_.-]{0,62}$/;
const agentIdPattern = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/;
const domainPattern = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const mcpServerPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const mcpToolPattern = /^[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}$/;
const netsuiteTypePattern = /^[a-z][a-z0-9_]{0,99}$/;
const quickstartToolPattern = /^[a-z][a-z0-9_]{0,63}$/;

/** Returns human-readable problems with a form (empty when it looks valid). */
export function validateForm(system: AccessSystem, form: AnyForm): string[] {
  const errs: string[] = [];
  if (isSaaS(system)) {
    const f = form as SaaSForm;
    if (!f.allObjects) for (const o of cleanList(f.objects)) if (!/^[A-Za-z0-9_][A-Za-z0-9_./$-]{0,159}$/.test(o)) errs.push(`Object "${o}" is not a valid name.`);
    const tenant = new RegExp(`^${system}:[a-z][a-z0-9_]{0,62}$`);
    if (!f.allTenants) for (const t of cleanList(f.tenants.map((x) => x.toLowerCase()))) if (!tenant.test(t)) errs.push(`Tenant "${t}" must be an integration id such as ${system}:default.`);
    if (!f.allTools) for (const t of cleanList(f.tools)) if (!/^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/.test(t)) errs.push(`MCP tool "${t}" is not a valid tool name.`);
    return errs;
  }
  switch (system) {
    case 'gmail': {
      const f = form as GmailForm;
      if (!Number.isInteger(f.maxRecipients) || f.maxRecipients < 0 || f.maxRecipients > 10000)
        errs.push('Max recipients must be a whole number between 0 and 10000.');
      break;
    }
    case 'github': {
      const f = form as GitHubForm;
      for (const r of cleanList(f.repos)) if (!repoPattern.test(r)) errs.push(`Repository "${r}" must look like owner/name.`);
      break;
    }
    case 'aws': {
      const f = form as AWSForm;
      for (const s of cleanList(f.services))
        if (!awsServicePattern.test(s)) errs.push(`Service "${s}" must be an IAM service prefix such as s3 or ec2 (lowercase).`);
      for (const a of cleanList(f.deniedActions))
        if (!awsDeniedPattern.test(a.toLowerCase())) errs.push(`Denied action "${a}" must look like service:Action (wildcards * and ? allowed).`);
      break;
    }
    case 'postgres': {
      const f = form as PostgresForm;
      const seen = new Set<string>();
      for (const u of f.upstreams) {
        const n = u.name.trim();
        if (n === '') continue;
        if (!upstreamPattern.test(n)) errs.push(`Upstream name "${n}" may contain letters, digits, _ . - and must start with a letter or _.`);
        if (seen.has(n)) errs.push(`Upstream "${n}" is listed twice.`);
        seen.add(n);
      }
      break;
    }
    case 'a2a': {
      const f = form as A2AForm;
      if (!Number.isInteger(f.maxDepth) || f.maxDepth < 1 || f.maxDepth > MAX_DELEGATION_DEPTH)
        errs.push(`Max depth must be a whole number between 1 and ${MAX_DELEGATION_DEPTH}.`);
      if (!f.anyAgent)
        for (const a of cleanList(f.mayDelegateTo)) {
          if (a === '*') errs.push('Use "Any agent" instead of listing *.');
          else if (!agentIdPattern.test(a)) errs.push(`"${a}" is not a valid agent id.`);
        }
      break;
    }
    case 'http': {
      const f = form as HTTPForm;
      const ds = cleanList(f.allowedDomains.map(normDomain));
      if (f.external === 'allowlist') {
        if (ds.length === 0) errs.push('An allowlist needs at least one domain (choose "None" to refuse all external egress).');
        for (const d of ds) {
          if (d === '*') errs.push('"*" is not a domain: choose "Any external domain" instead.');
          else if (d.length > 253 || !domainPattern.test(d)) errs.push(`"${d}" must be a domain such as api.example.com or *.example.org.`);
        }
      }
      break;
    }
    case 'mcp': {
      const f = form as MCPForm;
      const seen = new Set<string>();
      for (const sv of f.servers) {
        const n = sv.name.trim();
        if (n === '') continue;
        if (!mcpServerPattern.test(n)) errs.push(`MCP server name "${n}" is invalid.`);
        if (seen.has(n)) errs.push(`MCP server "${n}" is listed twice.`);
        seen.add(n);
        if (!sv.allTools)
          for (const t of cleanList(sv.tools)) {
            if (t === '*') errs.push(`Use "All tools" on ${n} instead of listing *.`);
            else if (!mcpToolPattern.test(t)) errs.push(`Tool "${t}" on ${n} is invalid.`);
          }
      }
      break;
    }
    case 'netsuite': {
      const f = form as NetSuiteForm;
      if (!f.allTypes)
        for (const t of cleanList(f.recordTypes.map((x) => x.toLowerCase())))
          if (!netsuiteTypePattern.test(t)) errs.push(`Record type "${t}" must be a NetSuite record type name such as customer or vendorbill.`);
      if (!f.allTools)
        for (const t of cleanList(f.quickstartTools)) if (!quickstartToolPattern.test(t)) errs.push(`QuickStart tool "${t}" must be a tool name such as read_record.`);
      if (!f.allTenants)
        for (const t of cleanList(f.tenants.map((x) => x.toLowerCase())))
          if (!netsuiteTenantPattern.test(t)) errs.push(`NetSuite integration "${t}" must be an integration id such as netsuite:acme.`);
      break;
    }
    default:
      break;
  }
  return errs;
}

/** One-line summary of a profile for history lists and cards. */
export function summarize(system: AccessSystem, profile: unknown): string {
  if (profile === null || profile === undefined) return 'No profile — all access denied (POL-020)';
  const f = toForm(system, profile);
  if (isSaaS(system)) {
    const sf = f as SaaSForm;
    const objs = sf.allObjects ? 'every object' : sf.objects.length ? `objects: ${sf.objects.join(', ')}` : 'no objects';
    const tenants = sf.allTenants ? 'every tenant' : `tenants: ${sf.tenants.join(', ') || 'none'}`;
    const tools = sf.allTools ? 'every MCP tool the mode allows' : `MCP tools: ${sf.tools.join(', ') || 'none'}`;
    return `mode: ${sf.mode}, ${objs}, ${tenants}, ${tools}`;
  }
  switch (system) {
    case 'gmail': {
      const g = f as GmailForm;
      return `send: ${g.send}, read: ${g.read ? 'yes' : 'no'}, max ${g.maxRecipients} recipients`;
    }
    case 'drive': {
      const d = f as DriveForm;
      return `mode: ${d.mode}, share: ${d.share}`;
    }
    case 'github': {
      const g = f as GitHubForm;
      const perms = [
        g.contents !== 'none' && `contents:${g.contents}`,
        g.pullRequests !== 'none' && `pull_requests:${g.pullRequests}`,
        g.issues !== 'none' && `issues:${g.issues}`,
        g.metadata !== 'none' && 'metadata:read',
      ].filter(Boolean);
      return `${g.repos.length} repo(s)${perms.length ? ', ' + perms.join(' ') : ', no permissions'}${g.allowDirectToken ? ', direct token' : ''}`;
    }
    case 'aws': {
      const a = f as AWSForm;
      return `mode: ${a.mode}, services: ${a.services.join(', ') || 'none'}${a.deniedActions.length ? `, denied: ${a.deniedActions.join(', ')}` : ''}`;
    }
    case 'postgres': {
      const p = f as PostgresForm;
      return p.upstreams.length ? p.upstreams.map((u) => `${u.name}: ${u.mode}`).join(', ') : 'no upstreams';
    }
    case 'a2a': {
      const a = f as A2AForm;
      const to = a.anyAgent ? 'any agent' : a.mayDelegateTo.length ? a.mayDelegateTo.join(', ') : 'nobody';
      return `may delegate to ${to}, max depth ${a.maxDepth}`;
    }
    case 'http': {
      const h = f as HTTPForm;
      if (h.external === 'allowlist') return `external: ${h.allowedDomains.join(', ') || 'no domains'}`;
      return h.external === 'any' ? 'external: any domain' : 'external: none';
    }
    case 'mcp': {
      const m = f as MCPForm;
      return m.servers.length ? m.servers.map((sv) => `${sv.name}: ${sv.allTools ? 'all tools' : sv.tools.join(', ') || 'no tools'}`).join('; ') : 'no MCP servers';
    }
    case 'netsuite': {
      const n = f as NetSuiteForm;
      const types = n.allTypes ? 'all record types' : n.recordTypes.length ? n.recordTypes.join(', ') : 'no record types';
      const tools = n.allTools ? 'all QuickStart tools the mode allows' : `QuickStart tools: ${n.quickstartTools.join(', ') || 'none'}`;
      const tenants = n.allTenants ? 'every NetSuite tenant' : `tenants: ${n.tenants.join(', ') || 'none'}`;
      return `mode: ${n.mode}, ${types}, SuiteQL: ${n.suiteql ? 'yes' : 'no'}, ${tools}, ${tenants}`;
    }
  }
}

export const SYSTEM_LABELS: Record<AccessSystem, string> = {
  gmail: 'Gmail',
  drive: 'Google Drive',
  github: 'GitHub',
  aws: 'AWS',
  postgres: 'PostgreSQL',
  a2a: 'Agent-to-agent',
  http: 'Web (HTTP)',
  mcp: 'MCP tools',
  netsuite: 'NetSuite',
  salesforce: 'Salesforce',
  servicenow: 'ServiceNow',
  sap: 'SAP',
};
