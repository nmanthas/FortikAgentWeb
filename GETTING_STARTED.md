# Fortik Agent Kill Switch: run it on your machine

This guide takes you from the zip file to a running Fortik with all five built phases demonstrated. It needs about 15 minutes, most of it waiting for the first build. Everything runs locally. No cloud accounts and no Docker are needed.

**What Fortik is, in one paragraph.** Companies are starting to let AI agents act on their own: query databases, send email, push code, call other agents. Fortik sits between those agents and the business systems. Every action an agent tries is first turned into a standard "action" record. Fixed rules (not an AI) label it **green** (safe: run it), **yellow** (risky: run a safer version, or wait for a human) or **red** (dangerous: stop it and lower the agent's permissions). Every decision is written to a tamper-evident log, the **Agent Diary**. Security staff can approve, undo, suspend, isolate or kill agents (one, a team, a swarm or the whole fleet) from a web console.

---

## 1. What is in the package

| Folder / file | What it is |
|---|---|
| `cmd/`, `internal/` | The Fortik server (Go): one program, `fortik` |
| `policies/` | The rules (OPA/Rego) that classify every action, with their tests |
| `migrations/` | The database schema |
| `web/console/` | The web console source (React). A built copy is already inside the server, so you don't need Node to use it |
| `scripts/dev-up.sh` | One-time local setup: private database, demo data, demo agents, secrets |
| `scripts/demo-phase*.sh` | One scripted, self-checking demo per phase |
| `configs/fortik.dev.yaml` | Local configuration (contains no secrets) |
| `docs/` | Design notes per phase, the policy catalogue, the API reference and the roadmap |
| `Fortik Agent Kill Switch — MVP Technical Implementation Plan.pdf` | The plan this follows |

**No secrets are included.** The setup script creates fresh random passwords, keys and tokens on your machine, in a hidden `.dev/` folder inside the project. Nothing leaves your machine.

---

## 2. Install the prerequisites (once)

You need:
- Go 1.27 or later;
- PostgreSQL 16 or 17 with the **pgvector** extension;
- Python 3, OpenSSL, curl, and `shasum` (macOS) or `sha256sum` with Perl's `shasum` (Linux).

Optional:
- `opa`, to run the policy tests;
- Node 20+, only if you want to rebuild the console.

### macOS (Homebrew)

```bash
brew install go postgresql@17 pgvector opa python
# Put the Postgres tools (initdb, pg_ctl, psql) on your PATH for this terminal and future ones:
echo 'export PATH="$(brew --prefix postgresql@17)/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Check that everything is installed:

```bash
go version          # go1.27 or newer (older Go 1.21+ downloads the right version automatically)
pg_ctl --version    # PostgreSQL 16 or 17
python3 --version
opa version         # optional
```

> **Already have Postgres from the EnterpriseDB installer** (in `/Library/PostgreSQL/17`)? That works too. The scripts find it on their own, or you can set `export PGBIN=/Library/PostgreSQL/17/bin`. pgvector must be installed for that Postgres; the EDB "Stack Builder" offers it.

### Linux (Debian/Ubuntu)

```bash
sudo apt install -y postgresql-17 postgresql-17-pgvector python3 openssl curl perl
# Go: install 1.27+ from https://go.dev/dl/
export PGBIN=/usr/lib/postgresql/17/bin
```

You don't need to start or configure a system Postgres. The setup creates its own private database server on port **55432** and leaves any existing Postgres alone.

---

## 3. One-time setup

```bash
unzip FortikAgentWeb.zip        # or: tar xzf FortikAgentWeb.tar.gz
cd FortikAgentWeb
./scripts/dev-up.sh
```

**What happens:**
1. A private Postgres starts on `127.0.0.1:55432` (data in `.dev/pg`).
2. Fortik's own database is created, plus three simulated *customer* systems:
   - `acme_prod`: 12,480 customers and 5,000 orders;
   - `acme_staging`;
   - `acme_memory`: an agent "memory" store using pgvector.
3. Fortik is built (`bin/fortik`). The first build downloads the Go dependencies and takes a few minutes.
4. Demo agents are registered with their permissions ("access profiles"): a Claude Code agent, a finance agent, a text-to-SQL agent, support agents and a delegation chain.
5. Fresh secrets and demo tokens are written to `.dev/`.

It should end with:

```
Dev environment ready.
  config : configs/fortik.dev.yaml
  tokens : .dev/tokens.env   (source it for the demo scripts)
  start  : bin/fortik serve -config configs/fortik.dev.yaml
  console: http://127.0.0.1:8080  ...
```

Running it again is safe: it keeps your data and secrets.

---

## 4. Start Fortik (Terminal 1)

```bash
cd FortikAgentWeb
bin/fortik serve -config configs/fortik.dev.yaml
```

Leave this terminal open; it shows the server's log. Fortik is listening when you see lines like:

```
"msg":"pgproxy listening","addr":"127.0.0.1:6432"
"msg":"gateway listening","addr":"127.0.0.1:8090"
"msg":"api listening","addr":"127.0.0.1:8080"
```

| Port | What it is |
|---|---|
| 8080 | API and **web console** |
| 8090 | App gateway: Gmail, Drive and GitHub calls go through here |
| 6432 | Postgres proxy: agents connect to databases through Fortik |
| 9091 | Callout for agentgateway (MCP / agent-to-agent / HTTP traffic) |

One warning line is expected in the local setup: `approvals.allow_token_pairs is on ... (dev/demo only)` (see Phase 5).

---

## 5. Run the phase demos (Terminal 2)

Each demo is a script that drives Fortik the way real agents would, then **checks every result itself**. Each line prints `PASS` or `FAIL`, and the script ends with "all checks passed". Run them in order. Each one resets the demo state it needs, so you can re-run any of them.

```bash
cd FortikAgentWeb
./scripts/demo-phase1-accident.sh     # expect 14 PASS
./scripts/demo-phase2.sh              # expect 30 PASS
./scripts/demo-phase3.sh              # expect 32 PASS
./scripts/demo-phase4.sh              # expect 54 PASS
./scripts/demo-phase5.sh              # expect 36 PASS
```

These exact numbers were verified on a fresh copy of this package before it was sent.

### Phase 1: Foundations (the "accident" path)
**The story:** a coding agent (`claude_code_01`) makes the classic mistake. It cleans up staging, then drops a production table.

What the demo shows:
1. A normal read on staging: **green**, allowed.
2. A wide `DELETE` on staging: **yellow**. Fortik first snapshots the rows it will delete, then lets it run, so it can be undone.
3. `DROP TABLE orders` on **production**: **red**. It is held and nothing happens. Fortik offers a safe alternative (rename the table instead of dropping it), and the agent is automatically stepped down to **READ_ONLY**.
4. The agent's next production write is refused, but reads still work, so its workflow isn't broken.
5. Security clicks **undo**: the deleted staging rows come back, and a second undo is refused.
6. The Diary's hash chain is verified and a signed export is produced. Any edit to history would be detected.

### Phase 2: Broker and apps
**The story:** agents get only the access they need, only for as long as they need it.

What the demo shows:
- Console login and roles: admin, security, auditor and agent owner.
- **Integrations** (Google, GitHub, AWS, Postgres) are entered in the console. Until they are, those systems **fail closed**: nothing goes through.
- Each agent gets its own short-lived, least-privilege database role per session; Fortik never hands out the master password.
- **Access profiles** are enforced twice, by the rules and by the database itself.
- Gmail, Drive and GitHub calls go through Fortik's gateway.
- Owners may only *narrow* their agent's access, never widen it.
- Live events stream to the console, and everything lands in the Diary.

### Phase 3: Interception everywhere + the three manager use cases
What the demo shows:
- **Claude Code hook:** every tool call Claude Code makes (shell, file edits, web fetches) is checked by Fortik first. If Fortik is unreachable, the call is blocked (fails closed).
- **Approvals:** a held `DROP TABLE` can only be approved *as the safe rename*, never as the original.
- **Timed suspension:** for example, "GitHub off for this agent for 30 minutes".
- **UC1, delegation bypass:** agent A asks agent C to do what A itself may not. Blocked.
- **UC3, multi-level chain:** A → B → C, with every hop checked against A's permissions.
- **UC2, spawning anomaly:** an agent type expected to run at most 5 copies starts more. Flagged, and the extra copies are refused.

### Phase 4: Containment
**The story:** something is wrong; stop it at the right size.

What the demo shows:
- **Memory protection (plan scenario 5):** every write to an agent's memory is staged and can be undone for 10 minutes. A poisoned memory can be cut off, rolled back to a clean snapshot and restored.
- **Suspend and resume:** running copies are told to pause, and queued jobs are paused through a signed webhook. Resume reverses it.
- **Isolate:** the agent keeps internal read access only.
- **Team suspend:** a whole business unit (Support) at once.
- **Cancel queued work:** clearly marked as NOT reversible.
- **Kill:** permanent, and the agent's credentials are revoked.
- **Fleet E-Stop:** stops every agent at once, with honest per-step results.
- **Undo list:** shows what can still be undone and what cannot.

### Phase 5: Swarms, communication map, shadow agents, baselines
**Swarm (plan scenario 3):**
- An orchestrator spawns 40 workers that all send the same email.
- Sends 1–5 are delayed so they can be cancelled. The 6th trips the **Max-5 circuit breaker**: all 41 agents become one *swarm*, and further sends are held for **two** approvers.
- One **kill-swarm** click runs 7 steps:
  1. freeze the swarm;
  2. hold pending calls;
  3. cancel queued sends;
  4. revoke credentials;
  5. kill the workers;
  6. set the orchestrator to read-only;
  7. export a signed evidence bundle.
- Releasing a swarm needs two *different* approvers.

**Attack (plan scenario 1):** the finance agent follows a hidden instruction in an email.
- Its bulk read of 12,480 customer records is held (POL-113).
- Its Drive share link is narrowed.
- Its email out to an investor is held red.
- The agent is isolated automatically, and a signed Diary export documents it all.

**Shadow agent (plan scenario 7):**
- A forgotten script logs in to production with its own database password.
- Fortik's discovery finds it and registers it as a *discovered agent*: isolated, no owner.
- Security revokes it: the login is disabled and the live session is ended.

**Communication map:** who talks to what, in 5-minute windows. It includes:
- a path trace showing how customer data travelled from the database to an outside domain;
- the blast radius of an agent: everything it *could* reach;
- **hidden-signal** detection, such as data smuggled inside long encoded URL parameters.

**Approval queue and baselines:**
- Held calls are grouped by swarm, show "1 of 2 approvals" and can be denied in bulk.
- Each agent has a 14-day normal volume per action type. A burst far above it is held.

> In this local setup one person plays both approvers, using the security and admin tokens. The setting `approvals.allow_token_pairs: true` in `configs/fortik.dev.yaml` allows that. A real deployment keeps it off, so two API tokens never count as two people.

---

## 6. Look around the web console

Open **http://127.0.0.1:8080**, type one of these emails into **Dev login** and click it. There is no password: dev login works only on this local setup.

| Login | Role | Can |
|---|---|---|
| `security@acme.com` | security + auditor | see everything, approve, contain, revoke |
| `admin@acme.com` | admin | everything, including integrations |
| `auditor@acme.com` | auditor | read-only |
| `pranav.kumar@acme.com` | agent owner | see and narrow their own agent |

Best viewed **after running the demos**:

| Page | What to look at |
|---|---|
| **Command Center** (home) | Fleet status, active swarms, discovered agents, live event feed, E-Stop |
| **Agents** | Each agent's level, permissions, recent actions, containment buttons and **Baseline** tab |
| **Approvals** | Held actions: approve, deny, assign, bulk-deny; swarm groups with "N of 2 approvals" |
| **Map** | Communication map: Team / Agent / Swarm / External / Blast radius views, path trace, time replay |
| **Swarms** | The 41-agent swarm, its 7-step kill report, two-approver release |
| **Shadow** | Discovered credentials and agents; revoke / dismiss / register |
| **Alerts**, **Teams**, **Undo**, **Integrations** | Alerts; team suspend; what can still be undone; where real Google / GitHub / AWS accounts are entered |

---

## 7. Try it by hand (optional)

An agent connects to the "production" database **through Fortik's proxy** using its own Fortik token:

```bash
source .dev/tokens.env
# A read: allowed
PGPASSWORD=$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03 psql -h 127.0.0.1 -p 6432 -U text2sql_agent_03 -d acme_prod \
  -c 'SELECT count(*) FROM orders'
# Dropping a table: held, nothing happens
PGPASSWORD=$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01 psql -h 127.0.0.1 -p 6432 -U claude_code_01 -d acme_prod \
  -c 'DROP TABLE orders'
#  ERROR:  fortik: hold (red) by POL-101: irreversible DROP_TABLE on prod database (public.orders)
```

The held DROP appears in the console under **Approvals**. Like in Phase 1, it also steps `claude_code_01` down to READ_ONLY; re-running the Phase 1 demo resets it.

Ask Fortik directly how it would classify an action (the "decide" API):

```bash
source .dev/tokens.env
curl -s -X POST http://127.0.0.1:8080/v1/actions/decide \
  -H "Authorization: Bearer $FORTIK_TOKEN_INTERCEPTOR" -H 'Content-Type: application/json' \
  -d '{"agent_id":"finance_agent_07","system":"gmail","verb":"SEND","source":"app_gateway",
       "target":{"to":["someone@outside.example"],"external_domains":1},
       "payload_summary":{"recipients":1,"data_labels":["customer_pii"]}}' | python3 -m json.tool
```

The answer is **red**. On a fresh setup it is a `hold` by POL-201 (customer data emailed outside the company), and the agent is stepped down. After the Phase 5 demo the finance agent is already ISOLATED, so you get `deny` by POL-012 instead, with POL-201 listed under `matched`.

To put the Claude Code hook in front of a real Claude Code on your machine, see `scripts/install-claude-hook.sh` (optional).

---

## 8. Run the automated tests (optional)

These need the setup from step 3, with its database running. The Fortik server doesn't need to be running.

```bash
export FORTIK_TEST_PG_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'
go test ./...                      # about 1,100 tests; a few skip if optional tools (redis, nats, moto) are missing
opa test policies/                 # 460 policy tests (needs opa)
cd web/console && npm ci && npx vitest run && cd ../..   # 173 console tests (needs Node)
```

---

## 9. Stop, restart, reset

```bash
# Stop: press Ctrl+C in Terminal 1 (the server), then stop the private database:
pg_ctl -D .dev/pg stop            # or: $PGBIN/pg_ctl -D .dev/pg stop

# Start again later:
pg_ctl -D .dev/pg -l .dev/pg.log start     # or simply re-run ./scripts/dev-up.sh
bin/fortik serve -config configs/fortik.dev.yaml

# Start completely fresh (deletes all local data, secrets and tokens):
pg_ctl -D .dev/pg stop; rm -rf .dev bin
./scripts/dev-up.sh
```

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `pg_ctl: command not found` / `initdb not found` | Put the Postgres tools on your PATH (step 2), or `export PGBIN=/path/to/postgres/bin` |
| `extension "vector" is not available` | Install pgvector for the *same* Postgres version (`brew install pgvector`, or `apt install postgresql-17-pgvector`) and re-run `./scripts/dev-up.sh` |
| `could not bind ... port 55432` / `8080 already in use` | Another program uses the port. Stop it, or for the database run `FORTIK_DEV_PG_PORT=55433 ./scripts/dev-up.sh` (then also change the port in `configs/fortik.dev.yaml`) |
| `go: go.mod requires go >= 1.27.1` | Update Go (`brew upgrade go`), or allow the automatic download: `export GOTOOLCHAIN=auto` |
| A demo prints `connection refused` | The server isn't running: start it in Terminal 1 (step 4) |
| A demo shows a `FAIL` | Re-run that demo once (each demo resets its own state). If it still fails, send the script's output and the server log from Terminal 1 |

---

## 11. What is real, and what is not yet

- **Real and running locally:**
  - the rules engine;
  - the Postgres proxy and per-agent database roles;
  - the Diary (tamper-evident, signed exports);
  - approvals, undo and every containment action;
  - swarm detection and kill;
  - the communication map;
  - Postgres shadow-agent discovery;
  - baselines;
  - the console.
- **Needs real test accounts:**
  - Gmail, Drive, GitHub and AWS actions are fully wired, but those systems fail closed until test-account credentials are entered in the console under **Integrations**.
  - The demos use Fortik's decision API and local test doubles in their place.
  - Actual email delivery has not been tested against a real Google Workspace.
- **Not built yet: Phase 6 (pilot hardening).** That covers the 200 actions/second load test, a 10,000-action replay suite, chaos tests and retention for the map's history.
- **Speed:** a decision takes about 2.5 ms inside the server on a laptop (95% of decisions within 4.2 ms). The plan's target for the pilot is under 50 ms.

---

## 12. Where to read more

| Document | What it covers |
|---|---|
| `README.md` | Overview and layout |
| `docs/ROADMAP.md` | All six phases, and every place the build deliberately differs from the plan (with reasons) |
| `docs/PHASE2_DESIGN.md` … `docs/PHASE5_DESIGN.md` | How each phase works |
| `docs/POLICIES.md` | Every rule (POL-xxx): what it catches and what it does |
| `docs/API.md` | Every API endpoint and who may call it |
| `ARCHITECTURE.md`, `SECURITY.md` | Architecture and security model |
