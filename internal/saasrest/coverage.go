package saasrest

import (
	"fortik/internal/coverage"
	"fortik/internal/integrations"
)

var titles = map[string]string{
	integrations.SystemSalesforce: "Salesforce",
	integrations.SystemServiceNow: "ServiceNow",
	integrations.SystemSAP:        "SAP",
}

// Declaration is the coverage of a provider's REST connection (2026-10-28):
// built and tested against local fakes only. Native agents of the provider
// (e.g. Agentforce actions) do not pass through Fortik.
func Declaration(system string) coverage.Declaration {
	fake := "internal/saasrest tests against a LOCAL FAKE " + titles[system] + " API"
	todo := "connect a " + titles[system] + " test tenant and run Test connection, then the gateway checks"
	c := func(dim, status, ev, gap, fix string) coverage.Capability {
		return coverage.Capability{Dimension: dim, Status: status, Evidence: ev, Gap: gap, Fix: fix}
	}
	bypass := "an agent or integration holding its own " + titles[system] + " credentials calls the API directly"
	if system == integrations.SystemSalesforce {
		bypass += "; Agentforce agents act inside Salesforce and never pass through Fortik (Fortik decides the messages sent to them through its Agent API route, not what they then do)"
	}
	return coverage.Declaration{
		System: system, Title: titles[system] + " REST API", Integrations: []string{system, system + ":*"},
		Interception: "agents call the API through Fortik's gateway (/gw/" + system + "/...) with their Fortik token; every call is decided as system " + system + " before Fortik forwards it with its own credentials",
		Bypass:       bypass,
		Capabilities: []coverage.Capability{
			c(coverage.DimDiscovery, coverage.Unsupported, "", "Fortik does not inventory the provider's own agents or integrations", "review connected apps / OAuth clients in the provider"),
			c(coverage.DimIdentity, coverage.VerifiedTest, fake+" (each call carries the agent's Fortik token; the provider sees Fortik's integration user)", "not verified on a real tenant", todo),
			c(coverage.DimActivity, coverage.VerifiedTest, fake+" (every call is an action)", "only calls made through Fortik", todo),
			c(coverage.DimDelegation, coverage.VerifiedTest, "Decide's delegation checks apply to every system (policy tests)", "", ""),
			c(coverage.DimPreExec, coverage.VerifiedTest, fake+" (reads allowed under the profile; writes and actions held; deletes red; paths outside the API refused)", "not verified on a real tenant", todo),
			c(coverage.DimRevocation, coverage.VerifiedTest, fake+" (killing an agent or revoking its Fortik token stops its calls: it never holds provider credentials)", "Fortik's own credentials are revoked in the provider", "disable the integration user or OAuth client there"),
			c(coverage.DimSuspension, coverage.VerifiedTest, "policy tests: a timed "+system+" suspension and the access profile apply to REST and MCP alike", "", ""),
			c(coverage.DimUndo, coverage.NotBuilt, "", "no verified undo: every change is held for approval instead", ""),
			c(coverage.DimEvidence, coverage.VerifiedTest, fake+" (actions and Diary)", "", ""),
		},
	}
}
