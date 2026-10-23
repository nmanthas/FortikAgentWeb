# Security

Fortik sits on the authority path of autonomous agents. It must be **correct before fast** and **fail closed** for anything risky or unknown.

## Invariants (enforced and tested in Phase 1)

1. **No statement reaches a protected Postgres without a decision.**
   - Every non-trivial statement goes through Decide before it is forwarded.
   - Only transaction-control statements and an allowlist of harmless session statements skip Decide: BEGIN, COMMIT, SHOW, and SET of whitelisted GUCs.
   - `SET ROLE`, `SET SESSION AUTHORIZATION` and `session_replication_role` are classified as GRANT, which is red.
2. **Red never executes.**
   - The policy holds or denies every red action.
   - The Go engine additionally rejects any bundle output that pairs red with an executing decision.
3. **Unknown fails closed:** unknown verbs and systems (POL-002), unclassified SQL (POL-110), unparseable SQL, internal errors, and reduced forms the interception point can't honour.
4. **Automatic step-down only tightens control.** It is atomic with the decision and the Diary event, and it never loosens a level.
5. **Undo is claimed only when it was prepared.**
   - The undo handle is recorded before the statement runs, and the snapshot is taken in the same transaction.
   - An action with no handle returns "NOT undoable".
   - Concurrent or repeated undo requests can't both run, because claiming is atomic.
6. **The Diary is append-only and tamper-evident.**
   - Database triggers refuse UPDATE, DELETE and TRUNCATE.
   - The app role (`fortik_app` in dev) is not the table owner, so it can't disable those triggers.
   - Byte-exact hash chaining with a gapless seq lets verification detect edited, removed or reordered rows, and tail truncation through the head row.
   - Exports and daily roots are Ed25519-signed.
7. **Refusal inside a transaction aborts it.** A partially executed migration can't be committed after Fortik refuses one of its statements.

## Secrets

- No credential lives in the config file or in Fortik's Postgres. Configs reference secrets by name.
- Providers today are `file` (dev/pilots that mount secrets) and `env`. Vault and KMS arrive with the authority broker in Phase 2.
- API and agent tokens are stored only as SHA-256 hashes, compared in constant time, and reloaded without a restart.
- Logs and Diary events carry statement types, fingerprints, normalized SQL (constants replaced with `$n`), tables and data labels. They never carry raw literals, row data, tokens or passwords.
- `.dev/` (generated dev secrets) is gitignored. Dev secrets are random per checkout and must never be reused.

## Authentication and authorization (Phase 1)

- Bearer tokens with explicit roles per route:
  - `interceptor`: decide.
  - `auditor`: reads, Diary export, metrics.
  - `security`: undo.
  - `admin`: all of the above.
- Every security-state change is a Diary event that records the actor.
- Agent authentication at the proxy uses a per-agent bootstrap token, sent as cleartext-password auth (use the proxy's TLS option outside localhost).

## Known gaps, by design of the phase plan (not yet mitigated)

| Gap | Planned in |
|---|---|
| Agents still use a static upstream DB role through the proxy; no per-action short-lived credentials yet; agent tokens are long-lived bootstrap tokens | Phase 2 (authority broker) |
| An agent holding its *own* DB credentials can bypass the proxy entirely | Phase 2 (broker issues all credentials), Phase 5 (standing-credential discovery) |
| No OIDC/SSO for humans; no `PUT /level` API (CLI only, audited) | Phase 2 |
| No mTLS between components; proxy TLS optional | Phase 6 (TLS supported now if configured) |
| Snapshot tables in `fortik_undo` and memory snapshots are not separately encrypted: they stay in the customer's own database and rely on its at-rest encryption (Fortik stores pointers only). Purge jobs exist since Phase 4 | Phase 6 (optional envelope encryption) |
| Temporal: a running workflow pauses only if its worker uses the `temporalsdk` helper; Celery: messages a worker already prefetched cannot be held (cancel revokes them) — the containment step detail says so | Documented limitation |
| Memory restore and promotion commit in the customer's store before the Diary write (different databases); a Diary failure is retried and then reported as "applied but not recorded" | Documented limitation |
| User-defined SQL functions called from SELECT can have side effects the classifier can't see (known dangerous built-ins are caught) | Ongoing; documented limitation |
| Unqualified table names are assumed to be in `public` (search_path not resolved) | Documented limitation |
| Owner or superuser can still disable Diary triggers; detection then relies on verification and exported signed roots | Operational (run as non-owner; export roots off-box) |

## Reporting

Report security issues privately to the Fortik engineering team, not in public issues.
