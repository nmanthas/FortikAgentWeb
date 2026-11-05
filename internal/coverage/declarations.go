package coverage

// Built-in declarations. Every verified_live claim names the demo script that
// exercises it against the real system on the development environment
// (2026-10-24/25); verified_test names the automated test that exercises it
// against local fakes or test servers only. Update these when evidence changes.

func c(dim, status, evidence, gap, fix string) Capability {
	return Capability{Dimension: dim, Status: status, Evidence: evidence, Gap: gap, Fix: fix}
}

const needAccount = "Enter a disposable test account in console > Integrations, then run scripts/acceptance-real-accounts.sh"

// Declarations is what each integration's code can do today.
func Declarations() []Declaration {
	return []Declaration{
		{
			System: "postgres", Title: "PostgreSQL (wire-protocol proxy)", Interception: "agents connect to Fortik's proxy (:6432); every statement is decided before it is forwarded",
			Integrations: []string{"postgres:*"},
			Bypass:       "an agent holding its own database login can connect directly; shadow discovery finds such logins, and the network should allow only the proxy",
			Capabilities: []Capability{
				c(DimDiscovery, VerifiedLive, "demo-phase5.sh §C (standing login discovered)", "", ""),
				c(DimIdentity, VerifiedLive, "demo-phase2.sh §3 (per-agent role per session)", "", ""),
				c(DimActivity, VerifiedLive, "demo-phase1-accident.sh", "", ""),
				c(DimDelegation, VerifiedLive, "demo-phase3.sh UC1/UC3 (chain applied to every action)", "", ""),
				c(DimPreExec, VerifiedLive, "demo-phase1-accident.sh (DROP held, never forwarded)", "", ""),
				c(DimRevocation, VerifiedLive, "demo-phase2.sh §6 (role NOLOGIN, sessions terminated)", "", ""),
				c(DimSuspension, VerifiedLive, "demo-phase4.sh §C (POL-016)", "", ""),
				c(DimUndo, VerifiedLive, "demo-phase1-accident.sh (row snapshot restore), demo-phase3.sh §B (rename)", "UPDATE/DELETE with a narrow WHERE and INSERT are not snapshotted", "hold such writes for approval where reversal matters"),
				c(DimEvidence, VerifiedLive, "Diary verify in every demo", "", ""),
			},
		},
		{
			System: "claude_code", Title: "Claude Code (PreToolUse hook)", Interception: "the hook asks Fortik before every tool call; exit 2 blocks it; Fortik unreachable blocks it",
			BuiltIn: true,
			Bypass:  "only Claude Code tool calls pass the hook; install it through managed settings and give the agent no standing credentials",
			Capabilities: []Capability{
				c(DimDiscovery, Unsupported, "", "the hook does not list agents; coding agents are registered in Fortik", "register each coding agent (console > Agents)"),
				c(DimIdentity, VerifiedLive, "demo-phase3.sh §A (agent token)", "", ""),
				c(DimActivity, VerifiedLive, "demo-phase3.sh §A", "only tool calls made through Claude Code", ""),
				c(DimDelegation, Implemented, "Task subagent hops recorded (hook_task channel)", "subagents share the parent's identity", ""),
				c(DimPreExec, VerifiedLive, "demo-phase3.sh §A (force push, curl|sh, direct DB blocked; fail closed)", "", ""),
				c(DimRevocation, Unsupported, "", "the hook holds no credentials; Fortik revokes the agent's own tokens", ""),
				c(DimSuspension, VerifiedLive, "demo-phase3.sh §C (GitHub suspension covers gh/git)", "", ""),
				c(DimUndo, Unsupported, "", "shell commands are not reversible; risky ones are held instead", ""),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		{
			System: "agentgateway", Title: "agentgateway (MCP, A2A, HTTP egress)", Interception: "agentgateway v1.6.0 calls Fortik's gRPC callout (:9091) before forwarding; failure mode deny",
			BuiltIn: true,
			Bypass:  "only traffic routed through agentgateway is covered; agents must not reach tools or the internet directly",
			Capabilities: []Capability{
				c(DimDiscovery, Implemented, "", "agents are known by their Fortik token; unknown callers become shadow traffic findings", ""),
				c(DimIdentity, VerifiedLive, "demo-agentgateway.sh §1 (identity from the token; spoofed header replaced)", "", ""),
				c(DimActivity, VerifiedLive, "demo-agentgateway.sh", "", ""),
				c(DimDelegation, VerifiedLive, "demo-agentgateway.sh §3 (A2A delegation token, POL-601)", "", ""),
				c(DimPreExec, VerifiedLive, "demo-agentgateway.sh (POL-028, POL-601, fail closed)", "", ""),
				c(DimRevocation, Implemented, "", "the agent's Fortik token is revoked in Fortik; agentgateway holds no credentials", ""),
				c(DimSuspension, VerifiedTest, "TestEndToEndAgentgateway", "", ""),
				c(DimUndo, Unsupported, "", "MCP tool calls and HTTP requests have no generic reversal", ""),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		{
			System: "google_workspace", Title: "Google Workspace (Gmail, Drive) via the app gateway", Interception: "agents call Gmail/Drive through Fortik's gateway; the Google token never leaves Fortik",
			Integrations: []string{"google_workspace"},
			Bypass:       "agents or users with their own Google OAuth tokens; shadow discovery lists OAuth grants",
			Capabilities: []Capability{
				c(DimDiscovery, VerifiedTest, "TestGoogleOAuthGrants (fake)", "not run against a real Workspace", needAccount),
				c(DimIdentity, VerifiedTest, "gateway tests (fake)", "not run against a real Workspace", needAccount),
				c(DimActivity, VerifiedTest, "gateway tests (fake)", "not run against a real Workspace", needAccount),
				c(DimDelegation, VerifiedTest, "TestE2EUC1DelegationBypass (Gmail SEND)", "", ""),
				c(DimPreExec, VerifiedTest, "gateway tests (fake): delayed send, narrowed share, refusals", "not run against a real Workspace", needAccount),
				c(DimRevocation, VerifiedTest, "gateway holds the token; dropped on kill", "", needAccount),
				c(DimSuspension, VerifiedTest, "TestScenario4TimedSuspensions", "", needAccount),
				c(DimUndo, VerifiedTest, "TestDelayedSendCancelledViaUndo, TestDriveAnyoneLinkNarrowedAndUndone", "a sent email is not undoable", needAccount),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		{
			System: "github", Title: "GitHub (App installation tokens)", Interception: "gateway proxy or a broker-issued, narrowed installation token",
			Integrations: []string{"github"},
			Bypass:       "personal access tokens held by agents; shadow discovery lists PATs",
			Capabilities: []Capability{
				c(DimDiscovery, VerifiedTest, "TestGitHubScriptUsingPersonalToken (fake)", "not run against a real org", needAccount),
				c(DimIdentity, VerifiedTest, "broker tests (fake)", "", needAccount),
				c(DimActivity, VerifiedTest, "gateway tests (fake)", "", needAccount),
				c(DimDelegation, VerifiedTest, "policy tests", "", ""),
				c(DimPreExec, VerifiedTest, "TestGatewayEndToEnd (fake)", "", needAccount),
				c(DimRevocation, VerifiedTest, "DELETE /installation/token (fake)", "tokens minted by other Fortik processes expire within 1 h", needAccount),
				c(DimSuspension, VerifiedTest, "demo-phase3.sh §C refuses at the gateway before the integration check", "", needAccount),
				c(DimUndo, VerifiedTest, "GitHub ref restore / PR reopen (fake)", "", needAccount),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		{
			System: "aws", Title: "AWS (STS sessions)", Interception: "15-minute STS sessions allowing exactly the requested action",
			Integrations: []string{"aws"},
			Bypass:       "IAM users with long-lived keys; shadow discovery lists them",
			Capabilities: []Capability{
				c(DimDiscovery, VerifiedTest, "TestAWSDiscoverAndRevoke (fake)", "", needAccount),
				c(DimIdentity, VerifiedTest, "SourceIdentity = agent (fake)", "", needAccount),
				c(DimActivity, Implemented, "", "CloudTrail is not ingested; Fortik sees only what it issued", "ingest CloudTrail (not built)"),
				c(DimDelegation, VerifiedTest, "policy tests", "", ""),
				c(DimPreExec, VerifiedLive, "demo-phase2.sh §5 (IAM refused by policy before any AWS call)", "only issuance is decided; calls made with an issued session are not intercepted", ""),
				c(DimRevocation, VerifiedTest, "deny by aws:TokenIssueTime (fake)", "STS sessions cannot be recalled; the deny can take time to propagate", needAccount),
				c(DimSuspension, VerifiedTest, "policy tests", "", needAccount),
				c(DimUndo, Unsupported, "", "AWS resource deletion is held as red instead", ""),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		{
			System: "copilot_connector", Title: "SaaS copilot connectors (Fortik-issued OAuth clients)", Interception: "the copilot's connector uses Fortik as its OAuth server; each token issue is a decision",
			Integrations: []string{"google_workspace", "github"},
			Bypass:       "a copilot connected with its own OAuth client, not Fortik's",
			Capabilities: []Capability{
				c(DimDiscovery, Implemented, "", "connectors are registered in Fortik, not discovered", ""),
				c(DimIdentity, VerifiedTest, "demo-phase6.sh §E (fake Google)", "", needAccount),
				c(DimActivity, VerifiedTest, "vendor audit pulls (fake)", "audit logs arrive after the fact", needAccount),
				c(DimDelegation, Unsupported, "", "the copilot's internal reasoning and hops are not visible", ""),
				c(DimPreExec, VerifiedTest, "token issue decided (fake Google)", "only token issuance is decided, not each API call", needAccount),
				c(DimRevocation, VerifiedTest, "demo-phase6.sh §E (kill revokes the upstream grant)", "", needAccount),
				c(DimSuspension, VerifiedTest, "timed suspension of the upstream system", "", needAccount),
				c(DimUndo, Unsupported, "", "", ""),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		{
			System: "memory", Title: "Agent memory (Postgres + pgvector) via the memory gateway", Interception: "agents read and write memory only through Fortik",
			Integrations: []string{"memory:*"},
			Capabilities: []Capability{
				c(DimDiscovery, Unsupported, "", "", ""),
				c(DimIdentity, VerifiedLive, "demo-phase4.sh §A", "", ""),
				c(DimActivity, VerifiedLive, "demo-phase4.sh §A", "", ""),
				c(DimDelegation, VerifiedTest, "policy tests", "", ""),
				c(DimPreExec, VerifiedLive, "demo-phase4.sh §A/B (POL-904 hold, POL-901 cut)", "", ""),
				c(DimRevocation, Unsupported, "", "agents never hold memory credentials", ""),
				c(DimSuspension, VerifiedLive, "demo-phase4.sh §B (memory cut)", "", ""),
				c(DimUndo, VerifiedLive, "demo-phase4.sh §A/B (staged writes, snapshot rollback)", "promoted writes are undone only by snapshot rollback", ""),
				c(DimEvidence, VerifiedLive, "Diary", "", ""),
			},
		},
		notBuilt("netsuite", "NetSuite", "Milestone 1"),
		notBuilt("salesforce", "Salesforce Agentforce", "Milestone 2"),
		notBuilt("sap", "SAP", "Milestone 3"),
		notBuilt("servicenow", "ServiceNow", "Milestone 4"),
	}
}

func notBuilt(system, title, milestone string) Declaration {
	d := Declaration{System: system, Title: title, Interception: "not built", Milestone: milestone}
	for _, dim := range Dimensions {
		d.Capabilities = append(d.Capabilities, c(dim, NotBuilt, "", "no connector yet", milestone+": needs a test tenant and the platform's documented APIs"))
	}
	return d
}

// Replace swaps the declaration of d.System (e.g. a not-built placeholder for
// the connector's own declaration); unknown systems are appended.
func Replace(decls []Declaration, d Declaration) []Declaration {
	for i := range decls {
		if decls[i].System == d.System {
			decls[i] = d
			return decls
		}
	}
	return append(decls, d)
}
