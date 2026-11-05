package nsquickstart

import (
	"fmt"
	"net/url"
	"strings"

	"fortik/internal/integrations"
)

// kind is one MCP connection type served by this package.
type kind struct {
	provider string // the business system its tool calls are decided as
	title    string // e.g. "QuickStart", "Salesforce MCP"
	// hosts are permitted without mcp_upstreams.allowed_hosts: exact names,
	// or suffixes when they start with a dot. Their addresses must still be
	// public.
	hosts       []string
	mappingFile string
}

var kinds = map[string]kind{
	integrations.SystemNetSuiteQuickStart: {provider: "netsuite", title: "QuickStart", mappingFile: MappingFile},
	integrations.SystemNetSuiteMCP:        {provider: "netsuite", title: "NetSuite MCP", hosts: []string{".suitetalk.api.netsuite.com"}, mappingFile: MappingFileAIConnector},
	integrations.SystemSalesforceMCP: {provider: "salesforce", title: "Salesforce MCP", hosts: []string{"api.salesforce.com", ".my.salesforce.com"},
		mappingFile: "fortik/salesforce_mcp/data.json"},
	integrations.SystemServiceNowMCP: {provider: "servicenow", title: "ServiceNow MCP", hosts: []string{".service-now.com", ".servicenowservices.com"},
		mappingFile: "fortik/servicenow_mcp/data.json"},
	integrations.SystemSAPMCP: {provider: "sap", title: "SAP MCP", mappingFile: "fortik/sap_mcp/data.json"},
}

// MCPSystems are the MCP connection types, in display order.
var MCPSystems = []string{integrations.SystemNetSuiteQuickStart, integrations.SystemNetSuiteMCP,
	integrations.SystemSalesforceMCP, integrations.SystemServiceNowMCP, integrations.SystemSAPMCP}

// Providers whose tenants have an MCP endpoint /mcp/<provider>/<tenant>.
var Providers = []string{"netsuite", "salesforce", "servicenow", "sap"}

// isMCPSystem reports whether a connection type is an MCP connection here.
func isMCPSystem(system string) bool {
	_, ok := kinds[system]
	return ok
}

// providerOf is the business system of a connection type ("netsuite" for
// an unknown one, as before multi-provider support).
func providerOf(system string) string {
	if k, ok := kinds[system]; ok {
		return k.provider
	}
	return System
}

func kindTitle(system string) string {
	if k, ok := kinds[system]; ok {
		return k.title
	}
	return "NetSuite MCP"
}

// builtinHost reports whether host is one of a connection type's own hosts.
func builtinHost(system, host string) bool {
	for _, h := range kinds[system].hosts {
		if h == host || (strings.HasPrefix(h, ".") && strings.HasSuffix(host, h)) {
			return true
		}
	}
	return false
}

// genericSettings reads a Salesforce, ServiceNow or SAP MCP connection.
// OAuth endpoints: Salesforce's My Domain /services/oauth2/*, the
// ServiceNow instance's /oauth_auth.do, /oauth_token.do and
// /oauth_revoke.do, or (SAP, customer-managed) the URLs entered.
func genericSettings(st Settings, r integrations.Resolved, str func(string) string) (Settings, error) {
	st.Endpoint, st.Auth = str("endpoint_url"), str("auth_type")
	if st.Endpoint == "" {
		return st, fmt.Errorf("%w: the MCP server URL is not set", integrations.ErrNotConfigured)
	}
	if st.Auth == "" {
		st.Auth = AuthOAuth
		if r.System == integrations.SystemSAPMCP {
			st.Auth = AuthBearer
		}
	}
	u, err := url.Parse(st.Endpoint)
	if err != nil || u.Host == "" {
		return st, fmt.Errorf("%w: the MCP server URL is invalid", integrations.ErrInvalid)
	}
	host := strings.ToLower(u.Host)
	st.Name, st.TenantLabel, st.AccountID = kindTitle(r.System)+" "+host, host, host
	st.ClientID, st.Scope, st.RedirectURI, st.ClientSecret = str("client_id"), str("scope"), str("redirect_uri"), r.Secrets["client_secret"]
	if st.RedirectURI == "" {
		st.RedirectURI = "http://127.0.0.1:8080" + integrations.MCPCallbackPath
	}
	switch r.System {
	case integrations.SystemSalesforceMCP:
		inst := strings.TrimRight(str("instance_url"), "/")
		if iu, err := url.Parse(inst); err == nil && iu.Host != "" {
			st.AccountID = strings.ToLower(iu.Host)
		}
		st.AuthorizeURL, st.TokenURL, st.RevokeURL = inst+"/services/oauth2/authorize", inst+"/services/oauth2/token", inst+"/services/oauth2/revoke"
		if inst == "" {
			st.AuthorizeURL, st.TokenURL, st.RevokeURL = "", "", ""
		}
		if st.Scope == "" && st.Auth == AuthOAuth {
			st.Scope = "mcp_api refresh_token"
		}
	case integrations.SystemServiceNowMCP:
		base := u.Scheme + "://" + u.Host
		st.AuthorizeURL, st.TokenURL, st.RevokeURL = base+"/oauth_auth.do", base+"/oauth_token.do", base+"/oauth_revoke.do"
	case integrations.SystemSAPMCP:
		st.AuthorizeURL, st.TokenURL, st.RevokeURL = str("authorize_url"), str("token_url"), str("revoke_url")
	}
	missing := func(what string) error {
		return fmt.Errorf("%w: %s is not set (required with %s)", integrations.ErrNotConfigured, what, st.Auth)
	}
	switch st.Auth {
	case AuthBearer:
		if st.Token = r.Secrets["access_token"]; st.Token == "" {
			return st, missing("the bearer token")
		}
	case AuthClientCreds:
		switch {
		case st.ClientID == "":
			return st, missing("the client ID")
		case st.ClientSecret == "":
			return st, missing("the client secret")
		case st.TokenURL == "":
			return st, missing("the token URL")
		}
	case AuthOAuth:
		switch {
		case st.ClientID == "":
			return st, missing("the client ID")
		case st.AuthorizeURL == "" || st.TokenURL == "":
			return st, missing("the authorization and token URLs")
		}
	default:
		return st, fmt.Errorf("%w: unsupported authentication %q", integrations.ErrInvalid, clip(st.Auth, 40))
	}
	return st, nil
}
