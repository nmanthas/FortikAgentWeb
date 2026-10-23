import { describe, expect, it } from 'vitest';
import type { Agent, Level, Me } from '../api/types';
import { accessEditMode, containmentPermissions, fleetPermit, levelPermissions } from './permissions';

const me = (roles: string[], email = 'u@example.com'): Me => ({
  kind: 'user',
  email,
  name: '',
  roles,
  authMethod: 'dev',
  csrf: 'x',
  devLoginEnabled: true,
  oidcEnabled: false,
});
const agent = (level: Level, sponsor = 'owner@example.com'): Agent => ({
  agentId: 'a1',
  name: '',
  type: '',
  platform: '',
  sponsor,
  businessUnit: '',
  workspaceUser: '',
  copyCap: 1,
  level,
  discovered: false,
});

describe('level permissions (mirror of §9)', () => {
  it('lets security step down, up one level and kill', () => {
    const p = levelPermissions(me(['security']), agent('SUPERVISED'));
    expect(p.canStepDown && p.canStepUp && p.canKill).toBe(true);
    expect(p.stepUpTarget).toBe('FULL');
    expect(p.stepDownTargets).toEqual(['READ_ONLY', 'ISOLATED', 'QUARANTINED']);
  });

  it('lets the owner step down and up but not kill', () => {
    const p = levelPermissions(me([], 'Owner@Example.com'), agent('READ_ONLY'));
    expect(p.canStepDown).toBe(true);
    expect(p.canStepUp).toBe(true);
    expect(p.canKill).toBe(false);
    expect(p.killWhy).toMatch(/security/);
  });

  it('gives an auditor no level changes, with explanations', () => {
    const p = levelPermissions(me(['auditor']), agent('FULL'));
    expect(p.canStepDown || p.canStepUp || p.canKill).toBe(false);
    expect(p.stepDownWhy).toMatch(/security role or ownership/);
    expect(p.stepUpWhy).toMatch(/already at FULL/);
  });

  it('only security may leave KILLED', () => {
    expect(levelPermissions(me([], 'owner@example.com'), agent('KILLED')).canStepUp).toBe(false);
    const sec = levelPermissions(me(['security']), agent('KILLED'));
    expect(sec.canStepUp).toBe(true);
    expect(sec.stepUpTarget).toBe('QUARANTINED');
    expect(sec.canStepDown).toBe(false);
  });

  it('admin implies every role', () => {
    expect(levelPermissions(me(['admin']), agent('FULL')).canKill).toBe(true);
  });

  it('access edit mode: security full, owner narrow, others none', () => {
    expect(accessEditMode(me(['security']), agent('FULL'))).toBe('full');
    expect(accessEditMode(me([], 'owner@example.com'), agent('FULL'))).toBe('narrow');
    expect(accessEditMode(me(['auditor']), agent('FULL'))).toBe('none');
  });
});

describe('containment permissions (mirror of PHASE4 §1 roles)', () => {
  it('lets the owner suspend, resume, isolate and cut memory, but not kill, cancel queues or run fleet ops', () => {
    const p = containmentPermissions(me([], 'owner@example.com'), agent('FULL'));
    expect([p.suspend.ok, p.resume.ok, p.isolate.ok, p.memoryRemove.ok, p.memoryRestore.ok]).toEqual([true, true, true, true, true]);
    expect([p.kill.ok, p.cancelQueue.ok, p.revokeTokens.ok, p.restoreSnapshot.ok]).toEqual([false, false, false, false]);
    expect(fleetPermit(me([], 'owner@example.com')).ok).toBe(false);
  });

  it('refuses an owner resuming an agent a fleet e-stop suspended; security may', () => {
    const stopped = { ...agent('FULL'), suspended: true, suspendedBy: 'estop:cop_123' };
    const owner = containmentPermissions(me([], 'owner@example.com'), stopped);
    expect(owner.resume.ok).toBe(false);
    expect(owner.resume.why).toMatch(/fleet e-stop/);
    expect(containmentPermissions(me(['security']), stopped).resume.ok).toBe(true);
    // An ordinary suspension can be lifted by the owner.
    expect(containmentPermissions(me([], 'owner@example.com'), { ...stopped, suspendedBy: 'user:owner@example.com' }).resume.ok).toBe(true);
  });

  it('D2: an owner may resume only a suspension they imposed themselves; anything else needs security', () => {
    const owner = me([], 'owner@example.com');
    const suspendedBy = (by: string | undefined) => ({ ...agent('FULL'), suspended: true, suspendedBy: by });
    expect(containmentPermissions(owner, suspendedBy('user:owner@example.com')).resume.ok).toBe(true);
    for (const by of ['user:sec@example.com', 'system:level', 'user:OWNER@example.com']) {
      const p = containmentPermissions(owner, suspendedBy(by));
      expect(p.resume.ok).toBe(false);
      expect(p.resume.why).toBe(`Lifting a suspension imposed by ${by} requires the security role.`);
    }
    // The server did not say who: the console cannot tell, so it is someone else's.
    expect(containmentPermissions(owner, suspendedBy(undefined)).resume.why).toBe('Lifting a suspension imposed by someone else requires the security role.');
    // Security may lift any of them; an agent that is not suspended can always be "resumed" (a no-op).
    expect(containmentPermissions(me(['security']), suspendedBy('user:sec@example.com')).resume.ok).toBe(true);
    expect(containmentPermissions(owner, { ...agent('FULL'), suspended: false, suspendedBy: undefined }).resume.ok).toBe(true);
    // A non-owner without security is told about the role first.
    expect(containmentPermissions(me([], 'other@example.com'), suspendedBy('user:other@example.com')).resume.why).toBe(
      'Requires the security role or ownership of this agent.',
    );
  });

  it('D2: an owner may restore memory access only when they cut it themselves', () => {
    const owner = me([], 'owner@example.com');
    const cut = (by: string | undefined, mode: Agent['memoryAccess'] = 'none') => ({ ...agent('FULL'), memoryAccess: mode, memoryAccessChangedBy: by });
    expect(containmentPermissions(owner, cut('user:owner@example.com')).memoryRestore.ok).toBe(true);
    expect(containmentPermissions(owner, cut('user:owner@example.com', 'staging_only')).memoryRestore.ok).toBe(true);
    for (const by of ['user:sec@example.com', 'estop:cop_1', 'system:quarantine']) {
      const p = containmentPermissions(owner, cut(by, 'staging_only'));
      expect(p.memoryRestore.ok).toBe(false);
      expect(p.memoryRestore.why).toBe(`Restoring memory access cut by ${by} requires the security role.`);
    }
    expect(containmentPermissions(owner, cut(undefined)).memoryRestore.why).toMatch(/cut by someone else requires the security role/);
    expect(containmentPermissions(me(['security']), cut('user:sec@example.com')).memoryRestore.ok).toBe(true);
    // Full access (or a server that does not report the mode): nothing to lift; the server decides.
    expect(containmentPermissions(owner, cut('user:sec@example.com', 'full')).memoryRestore.ok).toBe(true);
    expect(containmentPermissions(owner, agent('FULL')).memoryRestore.ok).toBe(true);
  });

  it('D1: only security may roll memory back to a snapshot as part of Restore memory', () => {
    expect(containmentPermissions(me(['security']), agent('FULL')).rollbackSnapshot.ok).toBe(true);
    const p = containmentPermissions(me([], 'owner@example.com'), agent('FULL'));
    expect(p.memoryRestore.ok).toBe(true);
    expect(p.rollbackSnapshot.ok).toBe(false);
    expect(p.rollbackSnapshot.why).toBe('Rolling memory back to a snapshot requires the security role.');
  });

  it('never offers resume on a KILLED agent, even to security', () => {
    const p = containmentPermissions(me(['security']), agent('KILLED'));
    expect(p.resume.ok).toBe(false);
    expect(p.kill.ok).toBe(false);
  });
});

describe('votedAlready (Phase 5)', () => {
  const vote = (approver: string) => ({ approver, decision: 'approve', at: 't' });
  it('matches a user by email and an API token by "token:<name>", as the server records them', async () => {
    const { votedAlready } = await import('./permissions');
    expect(votedAlready(me(['security'], 'Sec@Example.com'), [vote('user:sec@example.com')])).toBe(true);
    const token: Me = { ...me(['security'], ''), kind: 'token', name: 'dev-security' };
    expect(votedAlready(token, [vote('token:dev-security')])).toBe(true);
    expect(votedAlready(token, [vote('token:dev-admin')])).toBe(false);
    expect(votedAlready(token, [vote('user:dev-security')])).toBe(false);
  });
});
