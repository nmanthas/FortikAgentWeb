# pgproxy — Fortik's PostgreSQL wire-protocol proxy

Agents connect to `pgproxy` as if it were Postgres. Every statement is parsed
with the real PostgreSQL parser (libpg_query, via `internal/pgsql`), turned into
an `action.Action`, and decided by `decide.Decider` **before** any of it reaches
the upstream database. The decision is then enforced on the wire.

Fail closed, always: SQL that cannot be parsed or classified, a `Decide` error,
an unknown decision, or a reduced form the proxy cannot apply means the
statement is not executed and the client gets a clear error.

## Connection setup

| Client sends | Proxy does |
|---|---|
| `SSLRequest` | `S` + TLS handshake if `tls_cert_file`/`tls_key_file` are set, else `N` |
| `GSSENCRequest` | `N` |
| `CancelRequest` | looks up the proxy-issued pid/secret and sends a real `CancelRequest` to that session's upstream backend with the upstream's key |
| `StartupMessage` | protocol 3.0 only. A 3.2 request or `_pq_.*` options get `NegotiateProtocolVersion` (minor 0). `replication=...` is rejected |

* `user` is the **agent_id**. `database` selects the upstream: the
  integration `postgres:<database>` if one exists (Phase 2, below), else the
  YAML `upstreams[database]`. A database configured in neither gets FATAL
  `3D000`. This check runs after authentication, so nobody learns which
  databases exist without a token.
* `application_name=fortik:<instance_id>` sets the instance id. A value with the
  `fortik:` prefix that fails the action id pattern gets FATAL `28000`.
* Authentication uses `AuthenticationCleartextPassword`. The password is the
  agent's Fortik token. The secret named `agent_tokens_secret` holds JSON
  `{"<agent_id>": "<lowercase hex sha256(token)>"}`. It is re-read on every
  connection, so tokens can be rotated without a restart. The comparison is
  constant-time. A failure gets FATAL `28P01`.
* The upstream connection uses pgconn with
  `application_name=fortik:<agent_id>:<instance_id|->`, as the agent's own
  role for an integration-backed upstream, or as the YAML upstream's static
  user (`password_secret`) for a legacy one. It is then hijacked. The client
  receives `AuthenticationOk`, every upstream `ParameterStatus`, a
  proxy-generated `BackendKeyData`, and `ReadyForQuery`.
* If the upstream cannot be used, the client gets FATAL `08004` and nothing
  is forwarded: no access to that upstream in the agent's postgres access
  profile, an agent at QUARANTINED/KILLED (or unregistered), an integration
  that cannot be read or is incomplete (e.g. `admin_password` missing), or an
  upstream that cannot be reached or refuses the login.
* Only harmless client startup parameters are forwarded upstream
  (client_encoding, DateStyle, TimeZone, search_path, timeouts, ...).
  `options` (which could carry `-c role=...`) is dropped.

## Upstreams: integrations and legacy YAML (Phase 2)

Upstreams come from two places, merged per connection:

1. **Integration `postgres:<name>`** (entered in the console, read through
   `integrations.Source`, so changes apply without a restart). It wins over a
   YAML upstream with the same name. Settings: `host`, `port`, `database`,
   `sslmode`, `environment`, `admin_user`, `read_role`, `write_role`, and the
   secret `admin_password`.
2. **YAML `pgproxy.upstreams.<name>`** (Phase 1). Every agent shares the
   static `user`. This is "legacy": the proxy logs a warning the first time
   each one is used.

The proxy only falls back to YAML when the integration does not exist. If the
integration store fails, or the integration exists but is invalid or missing
its secret, the connection is refused with `08004`.

For an integration-backed upstream, `internal/broker/pgroles` runs on every
client connection, before the upstream login:

* It refuses unless the agent is registered and below QUARANTINED, and its
  postgres access profile gives that upstream `read_only` or `read_write`.
  `none`, a missing upstream, a missing profile or an unknown mode all mean
  no access.
* As `admin_user`, it ensures the role `fortik_a_<sanitized agent>_<6 hex>`.
  The hex is the sha256 of upstream and agent, so roles are per upstream: two
  upstreams on one cluster never share a role. The role gets:
  * `LOGIN INHERIT`.
  * No SUPERUSER, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS.
  * Membership in **exactly one** of `read_role` / `write_role`, with
    `INHERIT TRUE, SET FALSE` on PG 16+. Any other membership refuses the
    session.
  * A comment that ties it to (agent, upstream). An existing role with the
    managed name but another comment is never taken over.
* It sets a **new random 32-byte password for every client session**, sent
  as a SCRAM-SHA-256 verifier so the plaintext never reaches server logs,
  with `VALID UNTIL now() + broker.postgres_session_ttl`.
* The change runs in one admin transaction. The issuance is recorded through
  `RecordIssuance` with scope `{upstream, mode, role}` (never the password)
  before that transaction commits.
* A per-(agent, upstream) mutex plus a Postgres advisory lock are held until
  the proxy has logged in with the password. Concurrent sessions, and other
  Fortik processes, therefore cannot rotate it away in between.

The database's own privileges are a **second wall** behind policy. If policy
allowed an `INSERT` for a `read_only` agent, Postgres would still answer
`42501 permission denied`.

Revocation is `Manager.RevokeAgent`, called by `broker.RevokeAll` on
QUARANTINED/KILLED. On every integration-backed upstream it:

* runs `ALTER ROLE … NOLOGIN PASSWORD NULL`;
* runs `pg_terminate_backend` on the role's sessions, which ends the proxied
  sessions;
* returns what it actually achieved.

New sessions are then refused because issuance checks the control level under
the same lock.

### Operator setup per integration-backed upstream

```sql
CREATE ROLE fortik_admin LOGIN CREATEROLE PASSWORD '…';      -- admin_user
GRANT app_read, app_write TO fortik_admin WITH ADMIN OPTION;  -- needed on PG 16+
GRANT pg_signal_backend TO fortik_admin;                      -- revocation kills sessions
CREATE SCHEMA fortik_undo AUTHORIZATION fortik_admin;         -- undo snapshots
GRANT USAGE, CREATE ON SCHEMA fortik_undo TO app_write;
-- app_read: SELECT on the application's tables; app_write: SELECT/INSERT/UPDATE/DELETE.
-- fortik_admin also needs INSERT/UPDATE on tables it may restore (undo runs as it).
```

"Test connection" (`pgroles.Test`) checks each of these. It also checks that
`read_role` is not a member of `write_role`.

### Wiring (cmd/fortik)

```go
late := &pgroles.LateRecorder{}                  // broker <-> adapter cycle
roles, _ := pgroles.New(pgroles.Config{Integrations: src, Access: accessStore,
    Control: controlStore, Recorder: late, TTL: cfg.Broker.PostgresSessionTTL, Log: log})
brk := broker.New(dec, pool, d, accessStore, map[string]broker.Adapter{"postgres": roles, ...}, log)
late.Set(brk)                                    // issuance fails closed until then
px, _ := pgproxy.New(cfg.PGProxy, cfg.Undo, sec, dec, us, log, pgproxy.WithRoles(roles))
undoExec := pgundo.NewExecutor(cfg.PGProxy, sec, pgundo.WithIntegrations(src))
testers.Register(roles)                          // integrations.Registry: "postgres" tester
```

## Per-statement flow

1. `pgsql.Classify` splits the query into statements and walks each one's whole
   parse tree (CTEs, subqueries, `EXPLAIN ANALYZE` inner statements). Each
   statement takes the most dangerous verb found anywhere in it.
2. `TRANSACTION` and `SESSION` statements and empty queries are forwarded
   without a decision. **Every other statement is decided, including
   `SELECT`.**
3. Facts are added to the Action:
   * `where_narrow`: the `=` columns in the WHERE cover the primary key or a
     valid, non-partial, non-expression unique index. This comes from a catalog
     lookup on the same upstream session, cached per session and cleared after
     DDL.
   * `rows_estimate`: for DELETE/UPDATE that are not narrow, an internal plain
     `EXPLAIN (FORMAT JSON)`. It uses the input rows of a top `ModifyTable`
     node, because PG ≥ 14 reports 0 rows for ModifyTable itself.
     `GENERIC_PLAN` is used for `$n` parameters on PG ≥ 16. The estimate is
     skipped when the statement calls a function outside a small builtin
     allowlist, because planning can constant-fold IMMUTABLE user functions.
   * `undo_preparable`.
   Internal pre-queries run only when no client request is in flight and the
   transaction is not failed (`E`). They use `SET LOCAL statement_timeout =
   pre_query_timeout`. Inside a client transaction they run in a savepoint that
   is always rolled back, so the client's transaction is never disturbed. If a
   pre-query fails, the fact is left unset (`where_narrow=false`, no estimate,
   which is conservative).
   Postgres drops the unnamed prepared statement and the unnamed portal on
   every simple `Query`. While the client may still use one (after a client
   `Parse ''` or `Bind` to portal `''`, until its next simple Query or, for the
   portal, the end of the transaction), pre-queries run over the extended
   protocol on proxy-owned names (`__fortik_int_N`) instead. A parameterised
   `EXPLAIN ... GENERIC_PLAN` only works in a simple Query, so in that state
   `rows_estimate` is left unset for statements with `$n` parameters.
4. `Decide`. Then enforcement, below.

### Target contract (keys the Rego policy reads)

| key | type | meaning |
|---|---|---|
| `upstream` | string | config key of the upstream |
| `database` | string | upstream database name |
| `environment` | string | `prod` / `staging` / `dev` from the upstream config |
| `statement_type` | string | see `internal/pgsql` (SELECT, DELETE, DROP_TABLE, SET_ROLE, UNKNOWN, ...) |
| `tables` | []string | every relation referenced, `schema.table`, primary first. A schema-level target (`DROP SCHEMA s`, `GRANT ... ON ALL TABLES IN SCHEMA s`) is listed as `s.*`. CTE names hide only references inside their own scope |
| `schema`, `table` | string | primary relation (`table` is empty for a schema-level target) |
| `has_where` | bool | the deciding DELETE/UPDATE/SELECT has a WHERE |
| `where_narrow` | bool | see above. Only bare columns count: `id::int = 5` is not an equality on `id` |
| `volatile_where` | bool | the deciding DELETE/UPDATE/SELECT's WHERE may select different rows on each evaluation: a function not on a built-in IMMUTABLE/STABLE allowlist (`random()`, `nextval()`, `clock_timestamp()`, any user-defined function; `now()` is STABLE and fine), `TABLESAMPLE`, `LIMIT`/`OFFSET` or `SKIP LOCKED` in a subquery. Always present |
| `undo_preparable` | bool | DELETE: single table, no USING, no CTE, not `WHERE CURRENT OF`, `volatile_where=false`. UPDATE: same, and the table has a PK |
| `on_conflict_update` | bool | an INSERT in the statement has `ON CONFLICT ... DO UPDATE`. Always present (false for non-INSERT statements) |
| `merge_has_delete` | bool | a MERGE in the statement has a `WHEN ... THEN DELETE` clause (MERGE stays `statement_type=MERGE`, verb WRITE). Always present |
| `dangerous_functions` | []string | dangerous builtins called anywhere in the statement |
| `protocol` | string | `simple` or `extended` |
| `statement_count` | int | statements in the query string |
| `fingerprint` | string | pg_query fingerprint |
| `normalized_sql` | string | pg_query normalized SQL (constants replaced by `$n`). Literals that `pg_query.Normalize` leaves in place (COMMENT ON, rule and BEGIN ATOMIC bodies, COPY file names, ...) are redacted too by a token scan. Raw SQL is never stored |
| `safe_form` | object | only for single-table DROP TABLE / TRUNCATE: `{"kind":"pg_rename","sql":...,"trash_table":...}` |

Action fields set by the proxy:

* `system=postgres`, `source=pgproxy`
* `verb` comes from the classifier
* `action_id` is pre-assigned with `action.NewID("act")`. Snapshot names use it
* `reversible` is true only for READ
* `payload_summary.data_labels` come from `data_labels` rules (`schema.table`,
  `schema.*`, `*.table`) matched against every table. A schema-level target
  `s.*` matches every rule for schema `s` (dropping a schema drops all its
  tables)
* `payload_summary.rows_estimate` is set when it was computed

### Enforcement

* **allow**: the statement is forwarded unchanged.
* **allow_reduced**: the only reduced form the proxy understands is
  `{"snapshot_rows": true}`. Any other key, a non-true value, an empty reduced
  form, the extended protocol, a multi-statement query string, or
  `undo_preparable=false` means the statement is **refused**.
  * Idle session: `us.Prepare` (prepared) → internal `BEGIN ISOLATION LEVEL
    REPEATABLE READ` → `CREATE SCHEMA IF NOT EXISTS fortik_undo` →
    `CREATE TABLE fortik_undo.<table>_<ulid> AS SELECT * FROM <same relation,
    alias, ONLY> WHERE <same where>` → the original statement, with its results
    relayed but not its ReadyForQuery → `COMMIT` (or `ROLLBACK` if it failed) →
    `ReadyForQuery('I')`. The handle then moves to `active` (or `failed`).
    If the snapshot fails, the statement never runs.
  * Integration-backed upstream: the snapshot runs as the agent's own role.
    That role has no CREATE on the database, so `CREATE SCHEMA` is skipped and
    `fortik_undo` must already exist (the tester checks it). The snapshot
    table is owned by the agent's role, followed by
    `GRANT SELECT ON fortik_undo.<snapshot> TO <admin_user>`, because snapshot
    verification and undo (`pgundo`) run as the admin. A `read_only` agent
    cannot create snapshots, so its reduced-form writes are refused.
  * Inside a client transaction: schema and snapshot run inside it, then the
    statement is forwarded. When the client's transaction commits (a
    `COMMIT` command tag: COMMIT, END, COMMIT AND CHAIN), the proxy checks on
    a separate upstream connection that the snapshot table exists before the
    COMMIT result reaches the client (as the integration's admin user for an
    integration-backed upstream): `active` if it does, `failed` if it was
    discarded (`ROLLBACK TO SAVEPOINT`, `ROLLBACK; COMMIT`). A transaction
    that ends without a COMMIT tag (rollback, failed transaction, session end)
    makes the handle `failed`.
* **hold / deny / anything else**: the statement is not forwarded. The client
  gets `ErrorResponse` with SQLSTATE `42501` and:
  * Message `fortik: <hold|deny> (<class>) by <rule_id>: <reason>`
  * Detail `action_id=<id>`
  * Hint: the safe form when there is one ("A security approver can approve
    the safe form: ..."), otherwise "Ask an approver to review this action in
    Fortik".

  Inside a transaction block, or behind pipelined requests, the proxy makes
  Postgres itself raise that error (a `DO` block with `RAISE ... USING
  ERRCODE='42501'`). The upstream transaction is aborted exactly as if Postgres
  had raised it: later statements fail with `25P02` and `COMMIT` rolls back.
  The relayed error is replaced byte-for-byte by the proxy's own
  ErrorResponse, so no PL/pgSQL context leaks.
* **Multi-statement simple queries**: every statement is classified and
  decided. If any statement is not `allow`, nothing runs.
* **Extended protocol**: classify and decide at `Parse`.
  * On refusal, the error is sent at once (or injected in order behind earlier
    pipelined messages) and client messages are discarded until `Sync`. If
    anything earlier in the same batch was forwarded, or a transaction block is
    open, the raise is injected, so earlier pipelined statements in the same
    implicit transaction roll back.
  * Refused named statements are never created upstream. The refusal is
    raised on a proxy-owned statement and portal (`__fortik_refuse`), so the
    client's unnamed statement and portal survive it.
  * A statement prepared earlier is **decided again at every later `Bind`**.
    pgx caches prepared statements, so otherwise repeated executions would skip
    Fortik.
  * A statement is recorded only when Postgres confirms its `Parse`
    (`ParseComplete`). A Parse that Postgres rejects (`42P05` name already
    exists) or skips (an earlier message of the batch failed) never replaces
    what the proxy knows the name runs upstream: the old statement is decided
    again at its next Bind, and a possibly dropped unnamed statement is
    forgotten. A Bind that names a statement whose Parse is still unanswered
    in an earlier batch waits for that answer.
  * Unknown statement names are refused with `26000`. Names starting with
    `__fortik_` are reserved for the proxy.
* Fastpath `FunctionCall` is refused, because it bypasses SQL entirely.
* **CancelRequest**: a statement running upstream is cancelled there. A
  CancelRequest that arrives while the proxy is still deciding a statement
  (or running its pre-queries or snapshot steps) is recorded: the Decide call
  is aborted and the statement is refused with `57014` instead of being
  forwarded (inside a transaction block this aborts the transaction, like a
  real cancel). Internal snapshot steps are never cancelled. A cancel that
  arrives when nothing is running is ignored, as in Postgres.

## Protocol coverage

* Simple query, extended query (Parse/Bind/Describe/Execute/Close/Flush/Sync),
  and pipelining of both.
* COPY FROM STDIN and COPY TO STDOUT (text and binary), over both protocols.
  For libpq-style extended-protocol COPY, the Sync that Postgres ignores in
  copy-in mode and the Sync sent after CopyDone are accounted as one batch.
  CopyBoth is relayed but only exists for replication, which is rejected.
* Asynchronous NoticeResponse, ParameterStatus and NotificationResponse are
  relayed at any time. Notices produced by internal queries are dropped.
* CancelRequest, Terminate, SSL, GSSENC (declined), protocol-version
  negotiation.
* Relay: one goroutine reads the upstream and writes to a 64 KiB buffered client
  writer. It does not flush per DataRow. It flushes on ReadyForQuery,
  CopyIn/Out/BothResponse and ErrorResponse, after every message following a
  client `Flush`, for async messages when idle, and every 10 ms otherwise.
  50k rows stream in about 0.2 s locally.
* Graceful shutdown: on context cancel the proxy stops accepting and closes
  every session and every connection still in startup.
* Transient accept errors (EMFILE, ENFILE, ECONNABORTED, ...) are retried with
  exponential backoff (5 ms to 1 s), like `net/http`. A fatal accept error
  closes every session before `Serve` returns it.

## Logging

Logs are structured (`slog`). Info-level decision logs carry agent, instance,
action id, statement type, verb, fingerprint, protocol, decision, class and
rule id. They never contain SQL text, literals or row data. Parse errors (which
can echo a token of the SQL) are logged only at debug level.

## Known limitations

* **search_path**: the classifier reports unqualified tables as `public.*`.
  Data labels, `schema` and `tables` use that assumption. The catalog lookups
  and the undo handle resolve the real schema with `to_regclass` in the
  session, but `safe_form` SQL uses `public` for unqualified names.
* **User-defined functions** are opaque. `SELECT my_func()` is a READ even if
  the function writes. Only the listed dangerous builtins are recognised,
  including built-ins that execute SQL passed as text (`query_to_xml*`,
  `ts_stat`, 2-argument `ts_rewrite`) and `schema_to_xml*`/`database_to_xml*`
  (which read tables without naming them). `table_to_xml('t')` takes the table
  as a string, so `t` is not listed in `tables`.
  Triggers, rules and views created earlier (as DDL, which is decided) can make
  allowed statements do more than they appear to. Statements inside
  `CREATE RULE` actions and `BEGIN ATOMIC` bodies do not change the DDL's
  classification (it stays DDL_CREATE; their tables are listed). A dangerous
  built-in call in such a body still makes the statement DANGEROUS_FUNCTION.
* **DROP DATABASE**: the database name is not part of the Target contract
  (`pgsql.Statement.Database` has it); policy should treat `DROP_DATABASE` as
  a whole.
* **SQL-level `PREPARE`/`EXECUTE`** are UNKNOWN (refused by policy). Use
  protocol-level prepared statements.
* **Snapshots are simple-protocol only.** Under the extended protocol,
  `allow_reduced` is refused.
* **Snapshot accuracy**: in the idle path, REPEATABLE READ makes the snapshot
  and the statement see the same rows. A concurrent change then surfaces as a
  serialization error (40001) instead of silently diverging. Inside a client
  transaction the client's isolation level applies: under READ COMMITTED a
  concurrent commit between snapshot and statement can make them differ.
  Volatile WHERE clauses are not snapshotted at all (`undo_preparable=false`);
  volatility is judged by function name against a built-in allowlist, and a
  user-defined *operator* with a volatile function is not detected.
* **Snapshot storage**: a legacy YAML upstream's user needs CREATE on the
  database for `fortik_undo`. Integration-backed upstreams need the schema
  pre-created (see Operator setup). Retention purging of `fortik_undo.*` is
  not implemented yet.
* **Per-agent roles (integration-backed upstreams)**:
  * `VALID UNTIL` only limits *logins*. A session opened before expiry keeps
    running, and every statement in it is still decided.
  * Issuance opens one admin connection per client session (no pool). This
    adds login latency, a few ms locally.
  * DDL the agent's role does not own (`DROP`, `TRUNCATE`, `ALTER`, and so the
    rename safe form) fails at the database unless the operator grants it.
    That is intended.
  * Undo of a rename safe form runs as the admin, so the admin must own (or
    be a member of the owner of) the table.
  * Roles are never dropped: one dormant role remains per (agent, upstream)
    ever issued.
* **Legacy YAML upstreams** cannot be revoked per agent: everyone shares the
  static user.
* **Rename safe form**: views and FKs follow the renamed (trash) table.
  `CREATE TABLE ... (LIKE ... INCLUDING ALL)` does not copy foreign keys and
  shares the trash table's sequences. `TRUNCATE ... RESTART IDENTITY` is not
  reproduced.
* **Decisions are per statement text and per execution**, not per row or per
  portal fetch. A portal executed in several `Execute` chunks is one decision.
* The client can still `SET application_name` (a SESSION statement), which
  hides the `fortik:<agent>:<instance>` marker on the upstream backend.
* TLS to the proxy is optional when configured: plaintext clients are still
  accepted, and the token is then sent in clear. Require TLS at the network
  layer for production.
* Refusing a fastpath `FunctionCall` inside a transaction block raises the
  error with a simple Query, which drops the client's unnamed statement
  (Postgres itself would keep it).
* A CancelRequest that arrives in the microseconds between a statement being
  queued and its bytes reaching Postgres can be lost, as with Postgres itself
  (cancellation is best-effort).
* Protocol 3.2 (long cancel keys) is negotiated down to 3.0.
