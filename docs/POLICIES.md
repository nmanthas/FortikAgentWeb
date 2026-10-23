# Policy catalogue (bundle `policies/`, query `data.fortik.decide.result`)

Rules are deterministic Rego. Each rule contributes a finding, `{rule_id, class, reason, reduced_form? | hold? | ladder? | deny?}`. `fortik.decide` then aggregates the findings:

- The worst class wins.
- The deciding rule is, within that class, a yellow finding that demands a hold first (it is why the action waits for a human), then the lowest rule id. (Phase 4: before this, a bulk email held by POL-203 was reported as POL-202.)
- Reduced forms from yellow findings are merged.
- The ladder target is the most restrictive level named by any red finding.
- Control gating can turn the decision into `deny`.

Thresholds are in `policies/fortik/data.json` and can be overridden per evaluation through `input.config`.

## Control ladder gating

| Rule | Level | Effect |
|---|---|---|
| POL-015 | unregistered agent | deny |
| POL-010 | KILLED | deny everything |
| POL-016 | SUSPENDED (Phase 4: suspend, team suspend, Fleet E-Stop) | deny everything until resumed; state and memory kept, nothing to re-earn |
| POL-011 | QUARANTINED | deny everything |
| POL-012 | ISOLATED | deny anything except internal READ |
| POL-013 | READ_ONLY | deny anything except READ |
| POL-014 | SUPERVISED | every yellow → hold for a human |

## Access profiles (Phase 2, `policies/fortik/access`)

They apply only when the agent's system has an access profile (gmail, drive, github, aws, postgres). The decision is deny, with no ladder change, checked after the control gate.

| Rule | Denies when |
|---|---|
| POL-020 | No profile for the system, or the mode/send/upstream is `none` |
| POL-021 | The profile is `read_only` and the verb isn't READ |
| POL-022 | Gmail `send: internal_only` and the message goes to an external recipient |
| POL-023 | Drive `share` is `internal_only`/`none` and the share is external, anyone, or not allowed |
| POL-024 | The GitHub repo isn't in `repos`, or the operation's permission is missing |
| POL-025 | The AWS service isn't in `services`, or the action matches `denied_actions` |
| POL-026 | The Postgres upstream isn't in the profile, or it is `read_only` and the verb isn't READ |
| POL-027 | Recipients exceed `max_recipients` |

## System-independent

| Rule | Class | Effect |
|---|---|---|
| POL-001 | red | any GRANT (permission, role or IAM change) → hold, step to ISOLATED |
| POL-002 | red | unknown verb or system → deny (no step-down) |
| POL-003 | red | sensitive data sent/exported/written to an external destination on any system other than Gmail/Drive → hold, ISOLATED |
| POL-005 | yellow | non-READ action on a known system with no dedicated rules yet (mcp, a2a, http, shell, memory) → hold |
| POL-007 | yellow | Gmail/Drive DELETE (not undoable in the MVP) → hold |
| POL-008 | yellow | spend above `spend_approval_usd` (500) on systems other than AWS, or any SPEND with no cost estimate → hold |
| POL-009 | red | malformed target field (boolean field not boolean, `external_domains` not a number) → deny (no step-down) |

## Postgres (Action produced by the Fortik proxy)

| Rule | Class | Effect |
|---|---|---|
| POL-101 | red | DROP TABLE/SCHEMA/DATABASE or TRUNCATE (any env) → hold, step to `pg_destructive_ladder` (READ_ONLY); rename safe form offered |
| POL-102 | yellow | DELETE/UPDATE with non-narrow WHERE, or over `pg_snapshot_row_threshold` (100) rows → `allow_reduced {snapshot_rows}` |
| POL-103 | yellow | Same as POL-102 but a snapshot can't be prepared (multi-table, no PK for UPDATE, over `pg_snapshot_max_rows`) → hold |
| POL-104 | red | COPY TO/FROM PROGRAM or a server file, or dangerous functions (`pg_read_file`, `dblink`, `pg_terminate_backend`…) → hold, ISOLATED |
| POL-105 | yellow | COPY … TO STDOUT (bulk export) → hold |
| POL-106 | yellow | DDL, maintenance, LOCK or SELECT INTO on prod → hold (no undo for DDL) |
| POL-107 | red | ALTER TABLE … DROP COLUMN on prod → hold, READ_ONLY |
| POL-108 | yellow | DROP COLUMN outside prod → hold |
| POL-109 | yellow | DO block or CALL (can't be inspected statically) → hold |
| POL-110 | red | UNKNOWN or missing statement type → deny (no step-down) |
| POL-111 | yellow | MERGE (can update/delete many rows, no undo in the MVP) → hold |
| POL-112 | yellow | upsert (`INSERT … ON CONFLICT DO UPDATE`), an INSERT whose `on_conflict_update` flag is missing, or `COPY … FROM STDIN` on prod → hold |

## Gmail / Drive (Actions produced by the Phase 2 app gateway)

| Rule | Class | Effect |
|---|---|---|
| POL-201 | red | SEND with sensitive data labels to external recipients → hold, ISOLATED |
| POL-202 | yellow | external SEND → `allow_reduced {delay_send_seconds: 120}` (the cancel window) |
| POL-203 | yellow | SEND to more than `gmail_bulk_recipients` (25) recipients → hold |
| POL-211 | yellow | Drive "anyone" link, or external share without sensitive data → `allow_reduced {narrow_share: domain, record_permission}` |
| POL-213 | yellow | any other Drive EXPORT to an external destination → hold |
| POL-212 | red | Drive share of sensitive data with an external grantee → hold, ISOLATED |

## GitHub

| Rule | Class | Effect |
|---|---|---|
| POL-301 | red | force-push or branch delete on a protected branch → hold, ISOLATED |
| POL-302 | yellow | push or force-push to a protected-adjacent branch (`release/`, `hotfix/`, `staging`), branch delete, PR close → `allow_reduced {record_ref}` |
| POL-302 | yellow | ordinary push or PR merge to a protected branch → `allow_reduced {record_ref}` |
| POL-303 | red | workflow, secret, webhook or deploy-key changes, or a push touching `.github/workflows/` → hold, ISOLATED |
| POL-305 | yellow | workflow dispatch (runs CI with repository secrets) → hold |
| POL-304 | red | any other GitHub deletion (repository, release, tag, environment), by verb DELETE or by a `delete_*` operation name → hold, ISOLATED |

## AWS

| Rule | Class | Effect |
|---|---|---|
| POL-401 | red | non-read `iam:`, `organizations:`, `sso:` or `identitystore:` actions → hold, ISOLATED |
| POL-402 | red | DELETE of resources (by verb **or** by action name: `Delete*`, `Terminate*`, `Remove*`, `Purge*`, `Destroy*`, `Deregister*`), or backup deletion/modification → hold (not undoable in the MVP) |
| POL-401 (sts) | red | any `sts:` action except GetCallerIdentity/GetAccessKeyInfo/DecodeAuthorizationMessage (role chaining would escape the session policy) → hold, ISOLATED |
| POL-406 | yellow | SSM run-command/session, Lambda invoke and code/config update, KMS decrypt, ECS run-task/exec → hold |
| POL-405 | yellow | S3 lifecycle rules and Route 53 record changes (can delete data later or redirect traffic) → hold |
| POL-404 | red | permission/sharing changes outside IAM (`Put*Policy`, `Attach*Policy`, `*Permission`, `Authorize*`, ACLs, KMS `CreateGrant`, snapshot/AMI sharing) → hold, ISOLATED |
| POL-403 | yellow | `est_cost_usd` above `aws_spend_approval_usd` (500) → hold |

## Memory (Phase 4, `policies/fortik/memory`)

Memory actions come from the memory gateway (`/gw/memory/{store}/{namespace}/...`, system `memory`) or from MCP servers listed in `data.fortik.memory.mcp_servers`. `input.context.memory.access` is the agent's memory access mode (`full`, `staging_only`, `none`).

| Rule | Class | Effect |
|---|---|---|
| POL-901 | gate | access `none` → deny every memory or memory-MCP action, READ included |
| POL-902 | gate | access `staging_only` → deny DELETE (reads and staged writes allowed) |
| POL-903 | yellow | REMEMBER → `allow_reduced {memory_staging: true}`: always staged, promoted after `memory.promotion_delay` (10 min) unless flagged, undoable (dropped) until then |
| POL-904 | yellow | memory write carrying a sensitive data label → hold |

A gateway REMEMBER that names its store and namespace is covered here, so POL-005 does not also hold it; memory DELETE is still held by POL-005. (The MCP rules keep POL-801–804.)

Population (Phase 4 addition): POL-705 also refuses actions by a copy whose status is `suspended`.

## Phase 5: swarms, baselines, hidden signals, shadow agents

| Rule | Class | Effect |
|---|---|---|
| POL-113 | yellow | bulk read of sensitive data: a SELECT from a table carrying a sensitive data label, estimated above `pg_bulk_read_rows` (5000) rows read → hold. The estimate is the rows **read** (the largest plan node, so `json_agg(…)` over the whole table counts every row). For a parameterised read it is at least the table size, unless it is a unique-key lookup, because generic plans use default selectivities. Nothing is planned over a view or other non-table relation before the decision |
| POL-114 | yellow | a SELECT of sensitive data with **no** row estimate (a function outside the safe built-ins, a view, a pipelined statement, an EXPLAIN error or timeout, a never-analysed table) → hold (fail closed: unknown size is never treated as small) |
| POL-651 | yellow | swarm breaker tripped: the same action (action hash; a Gmail SEND is identified by its recipient set) by more than `swarm.breaker_n` (5) distinct agents or registered copies in the window → every matching call is held for **two** distinct approvers. Approval grants carry their approval count, and a grant approved by fewer people than a hold needs releases nothing. A trip raises identical pending holds to two approvers. Postgres row writes are not counted |
| POL-652 | gate | a frozen (killed) swarm refuses DELEGATE, delegation to its members, and new copies |
| POL-653 | gate | a member of a frozen swarm may only READ and is issued no credentials |
| POL-659 | gate | malformed swarm context → deny (fail closed) |
| POL-660 | yellow | above-normal volume → hold. The baseline is `first_use_ceiling` (200) for a verb never used, at least that ceiling and at most 5× it while fewer than 6 hours are active, 5× the median with < 3 days of history, and mean + 3σ after that. It never fires at or below the busiest hour already seen, and only executed calls count. An *escalation* finding: green becomes a yellow hold, and a yellow that would run reduced is held instead. Dropped on anything already held, denied or red |
| POL-661 | yellow | malformed baseline context → hold (fail closed) |
| POL-671 | yellow | a URL query carries an encoded payload (base64, hex or percent-encoded) of at least `map.encoded_param_min` (256) characters → hold. The payload can be in one parameter's name or value, or split over several parameters. Parameters are split on `&` and `;`. A part is measured by its runs of encoding-alphabet characters, so an inserted `.` or `%26` does not hide it. Signature parameters of GCS, S3 and Azure signed URLs on the provider's own hosts are exempt. Adapters send only a summary (`target.encoded_params`), never the value |
| POL-680–684 | gate | a discovered agent with no owner may not reach outside, GRANT, DELEGATE, SEND, EXPORT or SPEND; while its credential is flagged for revocation it may only READ |
| POL-689 | gate | malformed shadow context → deny (fail closed) |

A hold needs as many distinct approvers as the most demanding finding asks for (`approvals_required`, default 1).

## Adapter contract

These are the Target keys each adapter must set:

- **postgres** (built): `statement_type`, `environment`, `tables`, `schema`, `table`, `has_where`, `where_narrow`, `undo_preparable`, `volatile_where`, `on_conflict_update`, `merge_has_delete`, `dangerous_functions`, `protocol`, `statement_count`, `fingerprint`, `normalized_sql`, and `safe_form` (for DROP/TRUNCATE). `payload_summary.rows_estimate` and `payload_summary.data_labels` go in the payload summary.
- **gmail** (Phase 2): `to`, `cc`, `bcc`, `external_domains`. `payload_summary.recipients` and `payload_summary.data_labels` go in the payload summary.
- **drive** (Phase 2): a share or link maps to verb `EXPORT`, with `operation: "share"`, `share_type` (`user|group|domain|anyone`) and `external`. Drive shares deliberately map to EXPORT, not GRANT, so the plan's yellow "narrow and record permission" path applies instead of the always-red GRANT rule.
- **github** (Phase 2): `repo`, `branch`, `operation`, `protected`, `paths`. Branch names are normalised (`refs/heads/` stripped, lower-cased) and operations lower-cased before matching.
- **aws** (Phase 2): `iam_action`, `resource`, `backup`, plus `est_cost_usd`.
