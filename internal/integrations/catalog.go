package integrations

// The provider catalog says, per provider and environment, which transports
// Fortik can connect and why a transport is unavailable. It is what the
// console's connection-method selector offers; it never claims more than
// the connection types (schemas) implement.

// TransportOption is one transport of one provider environment.
type TransportOption struct {
	Transport string `json:"transport"`        // rest_api | mcp | native
	System    string `json:"system,omitempty"` // the connection type implementing it, when available
	Title     string `json:"title"`
	Available bool   `json:"available"`
	// Reason explains an unavailable transport, or the prerequisites of an
	// available one.
	Reason string `json:"reason"`
	// Verified states the evidence behind the connection type: live (against a
	// real account), test (only against local fakes) or none.
	Verified string `json:"verified"`
}

// EnvironmentInfo is one environment of a provider (most have one, "").
type EnvironmentInfo struct {
	Environment string            `json:"environment"`
	Title       string            `json:"title"`
	TenantLabel string            `json:"tenant_label"` // what tenant_ref means here
	Transports  []TransportOption `json:"transports"`
}

// ProviderInfo is one application.
type ProviderInfo struct {
	Provider     string            `json:"provider"`
	Title        string            `json:"title"`
	MultiTenant  bool              `json:"multi_tenant"` // tenants are created explicitly (POST /v1/app-integrations)
	Environments []EnvironmentInfo `json:"environments"`
}

func (p ProviderInfo) environment(env string) (EnvironmentInfo, bool) {
	for _, e := range p.Environments {
		if e.Environment == env {
			return e, true
		}
	}
	return EnvironmentInfo{}, false
}

var providers = []ProviderInfo{
	{
		Provider: ProviderNetSuite, Title: "NetSuite", MultiTenant: true,
		Environments: []EnvironmentInfo{
			{
				Environment: EnvNetSuiteFull, Title: "NetSuite account (SuiteTalk)", TenantLabel: "NetSuite account ID",
				Transports: []TransportOption{
					{Transport: TransportREST, System: SystemNetSuite, Title: "REST API (SuiteTalk)", Available: true, Verified: "test",
						Reason: "Needs an integration record with OAuth 2.0 client credentials (M2M), a certificate mapped to a least-privilege role, and REST Web Services enabled. Verified only against a local fake so far."},
					{Transport: TransportMCP, System: SystemNetSuiteMCP, Title: "MCP Server (AI Connector Service)", Available: true, Verified: "test",
						Reason: "Needs the AI Connector Service integration record (public client, authorization code grant, AI Connector Service scope), a SuiteApp or custom tools, and a NetSuite user with a non-Administrator role holding MCP Server Connection to authorize Fortik. Tool calls are refused until each tool is mapped (policies/fortik/netsuite_mcp/data.json). Verified only against a local fake so far."},
				},
			},
			{
				Environment: EnvNetSuiteQuickStart, Title: "NetSuite QuickStart", TenantLabel: "QuickStart company (label)",
				Transports: []TransportOption{
					{Transport: TransportREST, Title: "REST API (SuiteTalk)", Available: false, Verified: "none",
						Reason: "QuickStart's documented interface for AI agents is its MCP server. SuiteTalk REST web services with OAuth 2.0 client credentials (integration records, certificates) are not part of QuickStart's documented setup, so Fortik does not offer a REST connection for a QuickStart company. A full NetSuite account is a separate integration."},
					{Transport: TransportMCP, System: SystemNetSuiteQuickStart, Title: "MCP Server (QuickStart)", Available: true, Verified: "live",
						Reason: "Needs MCP Server Enabled in QuickStart settings and a personal access token. Verified live on 2026-10-25 (reads, holds and refusals)."},
				},
			},
		},
	},
}

// saasProvider is a provider with one environment offering REST and MCP.
func saasProvider(provider, title, tenantLabel string, rest, mcp TransportOption) ProviderInfo {
	return ProviderInfo{Provider: provider, Title: title, MultiTenant: true,
		Environments: []EnvironmentInfo{{Environment: "", Title: title, TenantLabel: tenantLabel, Transports: []TransportOption{rest, mcp}}}}
}

func init() {
	providers = append(providers,
		saasProvider(ProviderSalesforce, "Salesforce", "My Domain host",
			TransportOption{Transport: TransportREST, System: SystemSalesforce, Title: "REST API", Available: true, Verified: "test",
				Reason: "Needs a connected app or external client app with the OAuth 2.0 client credentials flow (and a run-as user) or the JWT bearer flow, and a user with API Enabled and least privilege. Tested only against a local fake so far."},
			TransportOption{Transport: TransportMCP, System: SystemSalesforceMCP, Title: "MCP Server", Available: true, Verified: "test",
				Reason: "Needs a Salesforce Hosted MCP server (https://api.salesforce.com/platform/mcp/v1/...) and an external client app with the mcp_api scope; a Salesforce user authorizes Fortik. Every tool call is refused until the tool is mapped (policies/fortik/salesforce_mcp/data.json). Tested only against a local fake so far."}),
		saasProvider(ProviderServiceNow, "ServiceNow", "instance host",
			TransportOption{Transport: TransportREST, System: SystemServiceNow, Title: "REST API", Available: true, Verified: "test",
				Reason: "Needs an integration user (Basic) or an OAuth client using the client credentials grant (enabled on the instance), with roles and ACLs for the tables agents use. Tested only against a local fake so far."},
			TransportOption{Transport: TransportMCP, System: SystemServiceNowMCP, Title: "MCP Server", Available: true, Verified: "test",
				Reason: "Needs ServiceNow's MCP Server Console (Now Assist) and an OAuth inbound integration for Fortik. Every tool call is refused until the tool is mapped (policies/fortik/servicenow_mcp/data.json). Tested only against a local fake so far."}),
		saasProvider(ProviderSAP, "SAP", "API host",
			TransportOption{Transport: TransportREST, System: SystemSAP, Title: "REST API (OData)", Available: true, Verified: "test",
				Reason: "Needs an OData API exposed to a communication user (S/4HANA Cloud: a communication arrangement) or an OAuth client. Endpoints differ by SAP product. Tested only against a local fake so far."},
			TransportOption{Transport: TransportMCP, System: SystemSAPMCP, Title: "MCP Server", Available: true, Verified: "test",
				Reason: "SAP does not publish a native MCP endpoint for S/4HANA that Fortik could verify: this connects an MCP server you run or license in front of SAP, named explicitly and allowed in mcp_upstreams.allowed_hosts. Every tool call is refused until the tool is mapped (policies/fortik/sap_mcp/data.json). Tested only against a local fake so far."}),
	)
}

// single-transport providers: their one connection type, no MCP yet.
func singleProvider(s Schema) ProviderInfo {
	opts := []TransportOption{{Transport: s.Transport, System: s.System, Title: s.Title, Available: true, Verified: "see coverage"}}
	if s.Transport != TransportMCP {
		opts = append(opts, TransportOption{Transport: TransportMCP, Title: "MCP Server", Available: false, Verified: "none",
			Reason: "No MCP connection type is implemented for this provider in Fortik yet. An MCP server can be governed generically through agentgateway (system mcp)."})
	}
	return ProviderInfo{Provider: s.System, Title: s.Title, MultiTenant: s.Multi,
		Environments: []EnvironmentInfo{{Environment: "", Title: s.Title, Transports: opts}}}
}

// Providers returns the catalog: the multi-transport providers, then one
// entry per remaining connection type.
func Providers() []ProviderInfo {
	out := append([]ProviderInfo(nil), providers...)
	multi := map[string]bool{}
	for _, p := range providers {
		multi[p.Provider] = true
	}
	for _, s := range schemas {
		if multi[connMeta[s.System].provider] {
			continue // part of a multi-transport provider above
		}
		out = append(out, singleProvider(s))
	}
	return out
}

func providerByID(id string) (ProviderInfo, bool) {
	for _, p := range Providers() {
		if p.Provider == id {
			return p, true
		}
	}
	return ProviderInfo{}, false
}
