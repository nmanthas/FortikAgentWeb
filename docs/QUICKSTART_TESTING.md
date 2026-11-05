# Testing NetSuite QuickStart through Fortik

This guide tests the NetSuite QuickStart integration end to end against your real QuickStart company:
- reads through Fortik;
- writes held for approval, then run once;
- undo;
- refusals, suspension and the kill switch.

Steps 1–4 and 6–9 never change anything in NetSuite. Step 5 changes one field on a test record that you create, and then undoes it.

> Your QuickStart token is **read-write** (the card shows "Token scope: Read and write (inferred)"). Fortik holds every write for approval, but approve writes only on test records. Never approve payments, emails, deletes or preference changes on real data. For day-to-day use, create a second, read-only token and rotate to it (step 9).

## 0. Run the current build

The QuickStart endpoint for agents is in the new build.

```bash
cd ~/FortikAgentWeb
go build -o bin/fortik ./cmd/fortik
# stop your running server (Ctrl-C), then:
bin/fortik serve -config configs/fortik.dev.yaml
```

`fortik serve` does not migrate. This build adds migrations 0018 (logical integrations) and 0019 (Salesforce, ServiceNow and SAP connections). Apply them before starting the server, then re-apply the grants (see `scripts/dev-up.sh`):

```bash
FORTIK_DATABASE_URL='postgres://fortik_owner@127.0.0.1:55432/fortik?sslmode=disable' bin/fortik migrate
sed 's/{{app}}/fortik_app/g' migrations/app_grants.sql.tmpl | psql 'postgres://fortik_owner@127.0.0.1:55432/fortik?sslmode=disable'
```

Your QuickStart connection is kept as is. It becomes the MCP transport of the logical integration `netsuite:quickstart`.

## 1. Check the connection (console)

1. Open **Integrations**. NetSuite is one card (your QuickStart company, `netsuite:quickstart`) with a **Connection method** dropdown (docs/INTEGRATIONS.md):
   - **REST API (SuiteTalk)** shows *unavailable for this QuickStart account*, with the reason (SuiteTalk REST is not part of QuickStart's documented setup). A working MCP connection never makes REST look configured. To use SuiteTalk with a full NetSuite account, click **Connect a full NetSuite account with SuiteTalk REST**.
   - **MCP Server (QuickStart)** is selected: its form (name, tenant label, endpoint, transport, authentication, token expiry, token), its status and its buttons. Click **Test connection**. Check:
   - **Connected**, MCP 2025-06-18, 27 tools;
   - **Agent calls routed through Fortik: yes**.
2. Note the agent endpoint the card shows, normally `http://127.0.0.1:8090/mcp/netsuite_quickstart`. `http://127.0.0.1:8090/mcp/netsuite/quickstart` is the same tenant. Agents connect there with their **Fortik agent token**, never the QuickStart token.
3. **View tools** lists the 27 tools with their schemas. Write tools are labelled "documented: read-write tokens only".
4. Optional: open **Configure** and enter the token's **expiration date**, so the card warns 7 days before it stops working.

## 2. Run the automated live check (2 minutes, read-only)

```bash
QS_VERIFY_SPONSOR=<your email> ./scripts/verify-quickstart-live.sh
```

It creates two throwaway agents and then checks:
- reads run through Fortik;
- `update_record` and `delete_record` are held and do **not** run;
- refusals never reach NetSuite (read-only profile, unknown tool, bad arguments, `MCP_SERVER_ENABLED`);
- a timed NetSuite suspension blocks one agent and not another.

At the end it denies every held write and revokes the agents' tokens. Expected result: `ALL CHECKS PASSED … nothing executed`.

## 3. Create a test agent and connect an MCP client

1. Go to **Agents > New agent**, e.g. `qs-tester` (type `erp_agent`).
   - For **sponsor**, use a teammate's or test address, e.g. `finance-ops@yourcompany.com`.
   - Fortik does not let an agent's sponsor approve that agent's holds (`approvals.allow_owner_approval: false`), so if you sponsor it yourself you cannot approve its writes in step 5.
2. Open **Agents > qs-tester > Access > NetSuite** and set:
   - Mode **read_only**;
   - **All record types**;
   - SuiteQL off;
   - **All QuickStart tools the mode allows**.

   Save with a reason. Without a NetSuite profile every call is refused (POL-020).
3. In **Agents > qs-tester**, **issue a token**. It is shown once; copy it. - 
4. Point an MCP client at Fortik, for example Claude Code:

   ```bash
   claude mcp add --transport http fortik-quickstart http://127.0.0.1:8090/mcp/netsuite_quickstart \
     -H "Authorization: Bearer <qs-tester's Fortik agent token>"
   ```

   Other clients: Streamable HTTP, URL as above, header `Authorization: Bearer <Fortik agent token>`.

   **Do not** put the QuickStart token in the client. If an AI client has its own QuickStart token, Fortik cannot see or stop it.

   Without an MCP client, raw JSON-RPC works too:

   ```bash
   T=<agent token>
   curl -s http://127.0.0.1:8090/mcp/netsuite_quickstart -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_records","arguments":{"recordType":"Term","limit":5}}}'
   ```

## 4. Reads (nothing changes)

Ask the agent things like:
- "Which NetSuite record types can you see?" (`get_record_model`)
- "List my payment terms." (`list_records` Term)
- "Show my QuickStart to-do list." (`todo_list`)
- "Which reports can I run?" (`report_catalog`), then "Run the … report."

What to check:
- The agent sees only the 16 read tools, because its profile is read-only.
- The QuickStart card's **Last 24h** count goes up, and **Recent decisions** shows each call: `allow`, executed.
- **Activity** and the **Diary** show the action and an `mcp.tool.executed` event for each call.
- Each MCP result's `_meta` carries `fortik/action_id`.

## 5. A write: held, approved, run once, undone (on a test record)

1. **Prepare a test record:** in QuickStart, create a vendor or customer you own, e.g. "Fortik Test Vendor". Your company currently has none.
2. **Allow writes:** set `qs-tester`'s NetSuite profile to mode **read_write**. Reconnect the client so it sees all 27 tools; write tools say "[Fortik: … held for human approval …]".
3. **Ask for a write:** "Set the memo of vendor Fortik Test Vendor to 'tested by Fortik'."
   - The agent gets: *Fortik held this call for human approval and did NOT execute it (action act_…, POL-1120: … undo: the changed fields are snapshotted before the update)*.
   - NetSuite is unchanged.
4. **Approve it** in **Approvals** with a reason. You need the security role, and you must not be the agent's sponsor.
5. **Retry:** tell the agent "Approved — repeat exactly the same call."
   - It runs once: the result has `fortik/undo: available`, and the memo changed in QuickStart.
   - Asking it to repeat again is held again, because the approval was used.
   - A call with a different memo is held as a new request: an approval covers only those exact arguments.
6. **Undo:** in **Undo**, find the action and click **Undo** with a reason. The previous memo is written back; check it in QuickStart.
   - Undo is last-writer-wins: a change someone made to that field in between is overwritten, and the result says so.

What is **not** undoable, and therefore always held: creates, deletes, transforms, record actions, emails, attachments and preferences.

**Scripted alternative.** The same flow runs unattended on a contact the script creates. It changes NetSuite, so it runs only when you say so:

```bash
QS_ALLOW_WRITE=yes QS_VERIFY_SPONSOR=<an email that is not the security token's identity> ./scripts/verify-quickstart-write.sh
```

It checks, in order:
1. creates "Fortik / Verification - safe to delete": held, approved, runs once, a repeat is held;
2. sets its `workEmail`: held, approved, snapshotted, runs once;
3. **undoes** it: the empty value is restored;
4. tries to delete it: red, the approval is refused;
5. inactivates it: held, approved, runs once.

The contact is left inactive; delete it in QuickStart if you don't want to keep it. The script passed on the local fake on 2026-10-25. It has not yet been run on your tenant.

## 6. Refusals (do not approve these on real data)

| Ask the agent to… | Expected |
|---|---|
| delete the test vendor | held **red** (POL-1002). Approving it is refused: deletes are never run by Fortik; do it in QuickStart if needed. The agent steps down to READ_ONLY. |
| turn off the MCP server preference (`set_preferences` MCP_SERVER_ENABLED) | **denied** (POL-1102) |
| change a company preference such as TIMEZONE | held for **2 approvers** (POL-1103) |
| pay a vendor bill (`execute_record_transform` payVendorBill), void or approve an invoice, create a bank transfer or journal entry | held for **2 approvers** (POL-1105) |
| email an invoice (`send_record_email`) | held (POL-1106: external effect, a repeat sends twice) |
| a write with the profile back on read_only | **denied** (POL-021), not held |
| a call with wrong arguments, or a tool QuickStart does not offer | **denied** (POL-1101 / POL-002) before reaching NetSuite |

Each refusal appears in **Recent decisions** with its rule. NetSuite never receives it.

## 7. Timed suspension (kill switch for one app)

1. In **Agents > qs-tester > Suspensions**, add **NetSuite**, suspended, 15 minutes.
2. Every QuickStart call by `qs-tester` is now refused (POL-030), including `tools/list`. Other agents are unaffected.
3. **Release** it; calls work again.

## 7b. Delegation (authority laundering)

If a read-only agent hands its task to a read-write agent, for example over A2A through agentgateway, the delegate's QuickStart write on its behalf is refused (POL-601).
- This applies whether the delegate sends the delegation token (`X-Fortik-Delegation`) or Fortik infers it from the open hop.
- A forged token is refused (POL-604).
- This is verified in tests (`TestProxyDelegatedQuickStartWriteRefused`). To try it live, give the first agent an `a2a` profile allowing delegation to the second, and route the delegation through agentgateway (see the Phase 3 demos).

## 8. Agent-wide kill switch

- Set `qs-tester`'s level to **KILLED**, use **Fleet E-Stop**, or revoke its token. Its QuickStart calls stop immediately, and its MCP client cannot even list tools.
- The agent never held a QuickStart credential, so there is nothing left to revoke in NetSuite.

## 9. Token rotation, expiry, disconnect, alerts

Fortik re-checks the connection every 30 minutes (`mcp_upstreams.check_interval`). Each check is the same initialize and tools/list as Test connection; it never calls a tool. **Alerts** (and Slack, if `notify_slack` is configured) report:
- `quickstart_connection`: the connection stopped working, e.g. the token was revoked;
- `quickstart_token_expiry`: the expiry date you entered is 7 days away or has passed;
- `quickstart_tools_changed`: QuickStart changed its tools or their schemas.

Agents are always validated against the newest tool list.


- **Rotate:** create a new token in QuickStart (read-only recommended), then **Configure > Personal access token > Replace** and Save.
  - The card shows **Configuration saved but not tested**.
  - Agents' calls are refused (POL-1101: tool list not verified for this token) until you click **Test connection**.
  - The card then shows the new scope, e.g. "Read-only (inferred)", 16 tools.
- **Expired or revoked token:** Test connection shows **Authentication failed** (or **Token expired or revoked**, when QuickStart's message says so). Agents' calls fail as not executed.
- **Disconnect:** **Delete** on the card removes the token from Fortik, and agents' calls are refused.
  - It does **not** revoke the token in QuickStart: revoke it in QuickStart under Menu > Administration > QuickStart settings > Personal access tokens.

## 10. Several tenants and transports (optional)

- **Restrict an agent to one tenant:** in the agent's **Access > NetSuite** profile, untick **All NetSuite tenants** and list `netsuite:quickstart`. Calls to any other NetSuite tenant are refused on REST and MCP alike (POL-1010). List another tenant only, and its QuickStart calls are refused with POL-1010.
- **A full NetSuite account** (not QuickStart) is a separate tenant: **Add NetSuite tenant**, environment *NetSuite account*, with its account ID. Its card offers the REST API (SuiteTalk, OAuth client credentials) and the MCP server (AI Connector Service, OAuth authorization code: **Set up**, then **Authorize**, which opens NetSuite's consent screen). Both are tested only against local fakes so far, and no AI Connector tool is mapped, so every AI Connector tool call is refused until it is.
- Status APIs per connection: `GET /v1/integrations/netsuite_quickstart/mcp` (the old `/v1/saas/netsuite_quickstart` still works) and `GET /v1/app-integrations/netsuite:quickstart`.

## What these tests do not cover

- **Clients that bypass Fortik:** an AI client with its own QuickStart token or OAuth grant goes straight to NetSuite.
- **Changes made outside Fortik:** QuickStart's MCP tools expose no system notes or last-modified times, so such changes are not detected afterwards.
- **QuickStart's own permissions:** the token acts with its QuickStart user's permissions. Fortik narrows what agents may do, but it does not change QuickStart's own permission checks.
