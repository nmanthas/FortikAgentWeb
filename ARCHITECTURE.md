# Architecture (as built through Phase 1)

```
 agent (psql, ORM, Claude Code shell, text-to-SQL agent)
   │  Postgres wire protocol, user=agent_id, password=Fortik agent token
   ▼
 ┌──────────────────────── fortik serve (one Go binary) ────────────────────────┐
 │  pgproxy ──► pgsql.Classify (pg_query) ──► Action ──► decide.Service ◄── POST /v1/actions/decide
 │     │                                                    │   (other interception points,
 │     │ enforce: allow / allow_reduced (snapshot) /        │    Phase 2–3)
 │     │          hold / deny  (+ abort client txn)         ├─ control.Store  (level; Postgres)
 │     │                                                    ├─ policy.Engine  (embedded OPA, hot reload)
 │     │ undo.PGStore.Prepare → snapshot → run → Activate   └─ one transaction: actions, held_actions,
 │     ▼                                                         step-down, diary (hash chain)
 │  upstream Postgres (customer DB)          api: diary verify/export, actions/explain, held, undo
 └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Request path for one SQL statement

1. The proxy parses the statement with `pg_query`. It walks the whole tree (CTEs, subqueries, `EXPLAIN ANALYZE`) and maps it to a verb and a `statement_type`. If the SQL can't be parsed, the statement is refused.
2. For DELETE/UPDATE the proxy computes three facts on the same upstream session:
   - `where_narrow`: equality on every column of the primary key or a unique index.
   - `rows_estimate`: from `EXPLAIN`.
   - `undo_preparable`: whether a row snapshot can be taken.
3. It builds the Action (`system=postgres`, normalized SQL only, no literals) and calls Decide in-process.
4. Decide reads the agent's control state and evaluates `data.fortik.decide.result`. In **one transaction** it then:
   - re-checks the level (and re-evaluates if the level moved),
   - inserts the action,
   - inserts the held action if the statement is held,
   - applies the step-down if a red rule names one (only ever more restrictive),
   - appends the Diary events.
5. The proxy enforces the decision:
   - `allow`: forward the statement.
   - `allow_reduced` with `snapshot_rows`: prepare the undo handle, then `CREATE TABLE fortik_undo.<t>_<id> AS SELECT * … WHERE <same where>` in the same transaction, then run the statement, then activate the handle.
   - `hold` or `deny`: send `ERROR 42501` with the rule, reason, action_id and any safe form. If the client is inside a transaction, the upstream transaction is aborted too, so a partial migration can't commit.
   - Any reduced form the proxy doesn't understand is refused.

## Decision model

- **Classes:** `green`, `yellow` or `red`, exactly one per action. Each matching rule contributes a finding, and the worst class wins. The deciding rule is the lowest rule id within that class.
- **Decisions:** `allow`, `allow_reduced` (run only in the reduced form), `hold` (recorded, may be approved later), or `deny` (refused by the control level, or the action is unknown/unregistered).
- **Ladder** (`policies/fortik/control`): `FULL`, `SUPERVISED`, `READ_ONLY`, `ISOLATED`, `QUARANTINED`, `KILLED`. A gate refuses verbs above what the level allows. A red finding names a step-down target; the default is ISOLATED and POL-101 uses READ_ONLY. Decide applies a step-down only if it is more restrictive than the current level.
- **Engine safeguards:** the engine rejects malformed results, red with an executing decision, and `allow_reduced` without a reduced form. Any of these makes Decide fail closed.

## Fail behaviour

| Failure | Result |
|---|---|
| Policy evaluation error | `deny` (`FAIL-CLOSED`), recorded if the store is up |
| Control state / store unavailable | `deny`. READs fail open only if listed in `fail.green_read_allowlist` (empty by default) |
| Unparseable or unknown SQL, unknown verb or system | `deny` (POL-110 / POL-002) |
| Reduced form the interception point can't honour | refused by the interception point |
| Broken policy edit during hot reload | rejected; the previous bundle keeps deciding (Diary event `policy.reload_failed`) |

## Data model (Phase 1)

- `agents`: identity, sponsor, type, `level`.
- `actions`: every decided action, including attempts by unregistered agents. Stores the explanation (`decision_json`): matched rules, levels before and after, policy version.
- `held_actions`: the action, reason, rule, safe form, approver role and expiry.
- `undo_handles`: kind, `handle_json`, and status `prepared` → `active` → `undoing` → `used`, with side branches to `failed` and `expired`.
- `diary`, `diary_head`, `diary_roots`:
  - `hash = sha256(prev_hash_hex || body_json)` over the exact stored canonical JSON.
  - `seq` is gapless.
  - Triggers forbid UPDATE, DELETE and TRUNCATE.
  - Daily roots are signed with Ed25519.

## Choices made for Phase 1 (see ROADMAP deviations)

- **Decide runs in-process in the proxy.** The plan's mitigation is "decide locally in the gateway (no network hop to OPA)". The HTTP endpoint wraps the same service for out-of-process callers.
- **Control state lives in Postgres.** Redis arrives with heartbeats and baselines. Measured green-action overhead is p95 1.4 ms sequential, and 6.9 ms with 8 concurrent workers at about 2,300 decisions/s, on a dev laptop.
- **agentgateway:** the spike recommends GO-WITH-CONDITIONS ([report](docs/spikes/agentgateway-spike.md)). It is wired in Phase 3.
