package integrations

// Connection types of the SaaS providers Salesforce, ServiceNow and SAP:
// one REST connection type (internal/saasrest) and one MCP connection type
// (internal/nsquickstart, the shared MCP transport) per provider. Keys are
// <type> (the provider's default tenant) or <type>:<tenant>.
//
// Facts used here (checked 2026-10-28; anything unverified is configurable):
//   - Salesforce REST: OAuth 2.0 client credentials (a connected app or
//     external client app with a run-as user; the token endpoint is the My
//     Domain URL + /services/oauth2/token) or the JWT bearer flow
//     (certificate + username). Salesforce Hosted MCP servers live under
//     https://api.salesforce.com/platform/mcp/v1/... and use an external
//     client app's OAuth authorization code flow.
//   - ServiceNow REST: Basic authentication or the OAuth client credentials
//     grant (POST /oauth_token.do; it must be enabled on the instance).
//     ServiceNow's MCP Server Console serves
//     https://<instance>.service-now.com/sncapps/mcp-server/mcp/<server>
//     with OAuth authorization code (oauth_auth.do / oauth_token.do /
//     oauth_revoke.do).
//   - SAP: OData services (/sap/opu/odata/...) with a communication user
//     (Basic) or OAuth client credentials; endpoints differ by product. No
//     SAP-published MCP server was found: the MCP option is a customer- or
//     partner-managed server named explicitly.

const (
	SystemSalesforce    = "salesforce"
	SystemSalesforceMCP = "salesforce_mcp"
	SystemServiceNow    = "servicenow"
	SystemServiceNowMCP = "servicenow_mcp"
	SystemSAP           = "sap"
	SystemSAPMCP        = "sap_mcp"

	ProviderSalesforce = SystemSalesforce
	ProviderServiceNow = SystemServiceNow
	ProviderSAP        = SystemSAP

	// MCPCallbackPath is the OAuth redirect path of every MCP connection that
	// uses the authorization code flow (NetSuite keeps its own path too).
	MCPCallbackPath = "/v1/oauth/mcp/callback"
)

// MCP authentication types (auth_type).
const (
	AuthOAuthCode   = "oauth_authorization_code"
	AuthClientCreds = "oauth_client_credentials"
	AuthBearer      = "bearer_token"
)

func showWhen(field string, values ...string) map[string][]string {
	return map[string][]string{field: values}
}

// mcpFields are the authentication fields every generic MCP connection type
// shares; defaultAuth is first in the options.
func mcpFields(authOptions []string, authHelp string) []Field {
	oauth := []string{AuthOAuthCode, AuthClientCreds}
	return []Field{
		{Key: "auth_type", Label: "Authentication", Type: FieldSelect, Default: authOptions[0], Options: authOptions, Help: authHelp},
		{Key: "client_id", Label: "OAuth client ID", Type: FieldText, ShowWhen: showWhen("auth_type", oauth...),
			Help: "The client ID of the OAuth client registered for Fortik on the provider."},
		{Key: "scope", Label: "OAuth scope", Type: FieldText, ShowWhen: showWhen("auth_type", oauth...),
			Help: "Space-separated scopes to request. Leave empty to use the client's default scopes."},
		{Key: "redirect_uri", Label: "Redirect URI", Type: FieldText, Default: "http://127.0.0.1:8080" + MCPCallbackPath, ShowWhen: showWhen("auth_type", AuthOAuthCode),
			Help: "Fortik's OAuth callback (the address you open the console at, followed by " + MCPCallbackPath + "). Register exactly this URL as the client's callback."},
		{Key: "client_secret", Label: "OAuth client secret", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_type", oauth...),
			Help: "Required for client credentials; for the authorization code flow only when the client is confidential. Stored only in Fortik's secret store."},
		{Key: "access_token", Label: "Bearer token", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_type", AuthBearer),
			Help: "A token the MCP server accepts as Authorization: Bearer. Fortik cannot refresh it: replace it here before it expires."},
		{Key: "oauth_tokens", Label: "OAuth tokens", Type: FieldPassword, Secret: true, Managed: true,
			Help: "Obtained by Fortik (Authorize, or the client credentials grant). Never entered by hand."},
	}
}

var saasSchemas = []Schema{
	{
		System: SystemSalesforce,
		Title:  "Salesforce REST API",
		Fields: []Field{
			{Key: "instance_url", Label: "My Domain URL", Type: FieldText, Required: true,
				Help: "Your org's My Domain URL (Setup > My Domain), e.g. https://acme.my.salesforce.com or https://acme--uat.sandbox.my.salesforce.com. Tokens are requested from it and the REST API is called on it."},
			{Key: "auth_flow", Label: "OAuth flow", Type: FieldSelect, Default: "client_credentials", Options: []string{"client_credentials", "jwt_bearer"},
				Help: "client_credentials: a connected app or external client app with the Client Credentials Flow enabled and a run-as user. jwt_bearer: an app with a digital certificate (JWT Bearer Flow) and a pre-authorized user. Either way the run-as user's profile and permission sets decide what Fortik (and agents through it) can do: give it least privilege and API Enabled."},
			{Key: "client_id", Label: "Consumer key (client ID)", Type: FieldText, Required: true,
				Help: "From the app's OAuth settings (Manage Consumer Details)."},
			{Key: "username", Label: "Username", Type: FieldText, ShowWhen: showWhen("auth_flow", "jwt_bearer"),
				Help: "The Salesforce user the JWT names (sub); it must be pre-authorized for the app."},
			{Key: "audience", Label: "JWT audience", Type: FieldText, Default: "https://login.salesforce.com", ShowWhen: showWhen("auth_flow", "jwt_bearer"),
				Help: "https://login.salesforce.com for production and Developer Edition orgs, https://test.salesforce.com for sandboxes."},
			{Key: "api_version", Label: "API version", Type: FieldText, Default: "62.0",
				Help: "The REST API version Fortik tests with, e.g. 62.0. Test connection lists the versions your org offers."},
			{Key: "client_secret", Label: "Consumer secret", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_flow", "client_credentials"),
				Help: "Required for client_credentials. Stored only in Fortik's secret store; agents never receive Salesforce credentials."},
			{Key: "private_key_pem", Label: "Private key (PEM)", Type: FieldTextarea, Secret: true, ShowWhen: showWhen("auth_flow", "jwt_bearer"),
				Help: "Required for jwt_bearer: the RSA private key of the certificate uploaded to the app (PKCS#8 or PKCS#1)."},
		},
	},
	{
		System: SystemSalesforceMCP,
		Title:  "Salesforce MCP server",
		Fields: append([]Field{
			{Key: "endpoint_url", Label: "MCP server URL", Type: FieldText, Required: true,
				Help: "A Salesforce Hosted MCP server URL, e.g. https://api.salesforce.com/platform/mcp/v1/d/<mydomain>/platform/sobject-reads (Salesforce recommends the /d/<mydomain> form). Hosts other than api.salesforce.com must be listed in mcp_upstreams.allowed_hosts."},
			{Key: "instance_url", Label: "My Domain URL", Type: FieldText, ShowWhen: showWhen("auth_type", AuthOAuthCode, AuthClientCreds),
				Help: "Your org's My Domain URL; Fortik uses its /services/oauth2/authorize, /token and /revoke endpoints."},
		}, mcpFields([]string{AuthOAuthCode, AuthBearer},
			"oauth_authorization_code: an external client app (Salesforce Hosted MCP servers require one) with OAuth enabled, the scopes Access MCP servers (mcp_api) and refresh_token, and Fortik's redirect URI; a Salesforce user then authorizes Fortik and every tool runs as that user. bearer_token: a token you obtained elsewhere.")...),
	},
	{
		System: SystemServiceNow,
		Title:  "ServiceNow REST API",
		Fields: []Field{
			{Key: "instance_url", Label: "Instance URL", Type: FieldText, Required: true,
				Help: "e.g. https://acme.service-now.com (use a sub-production or developer instance first)."},
			{Key: "auth_type", Label: "Authentication", Type: FieldSelect, Default: "basic", Options: []string{"basic", "oauth_client_credentials"},
				Help: "basic: an integration user's user name and password. oauth_client_credentials: an OAuth application registry entry (or inbound integration) using the client credentials grant, which must be enabled on the instance (it is off by default); tokens come from /oauth_token.do. The user's roles and ACLs decide what Fortik (and agents through it) can do."},
			{Key: "username", Label: "User name", Type: FieldText, ShowWhen: showWhen("auth_type", "basic"),
				Help: "A dedicated integration user (Web service access only) with the least roles needed."},
			{Key: "client_id", Label: "Client ID", Type: FieldText, ShowWhen: showWhen("auth_type", "oauth_client_credentials"),
				Help: "From System OAuth > Application Registry (or Machine Identity Console > Inbound integrations)."},
			{Key: "test_tables", Label: "Tables to check", Type: FieldList, Default: []string{"incident", "change_request", "sys_user"},
				Help: "Test connection reads one record id from each (sysparm_limit=1, sys_id only) to report which tables the user can read. Nothing is written."},
			{Key: "password", Label: "Password", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_type", "basic"),
				Help: "Required for basic. Stored only in Fortik's secret store."},
			{Key: "client_secret", Label: "Client secret", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_type", "oauth_client_credentials"),
				Help: "Required for oauth_client_credentials. Stored only in Fortik's secret store."},
		},
	},
	{
		System: SystemServiceNowMCP,
		Title:  "ServiceNow MCP server",
		Fields: append([]Field{
			{Key: "endpoint_url", Label: "MCP server URL", Type: FieldText, Required: true,
				Help: "From MCP Server Console, e.g. https://acme.service-now.com/sncapps/mcp-server/mcp/sn_mcp_server_default. Hosts outside *.service-now.com must be listed in mcp_upstreams.allowed_hosts."},
		}, mcpFields([]string{AuthOAuthCode, AuthClientCreds, AuthBearer},
			"oauth_authorization_code: an OAuth inbound integration for Fortik (Machine Identity Console) with Fortik's redirect URI; a ServiceNow user authorizes Fortik and tools run as that user. Fortik uses the instance's /oauth_auth.do, /oauth_token.do and /oauth_revoke.do. oauth_client_credentials: only if the instance enables that grant. bearer_token: a token you obtained elsewhere.")...),
	},
	{
		System: SystemSAP,
		Title:  "SAP OData API",
		Fields: []Field{
			{Key: "product", Label: "SAP product", Type: FieldSelect, Default: "s4hana_cloud_public", Options: []string{"s4hana_cloud_public", "s4hana_private_or_onprem", "other_odata"},
				Help: "s4hana_cloud_public: SAP S/4HANA Cloud Public Edition (a communication user on a communication arrangement, e.g. SAP_COM_0008 for business partners). s4hana_private_or_onprem: SAP Gateway OData services on S/4HANA Cloud Private Edition or on premise. other_odata: another SAP OData API. Endpoints and roles differ by product: Fortik does not assume one from another."},
			{Key: "api_base_url", Label: "API base URL", Type: FieldText, Required: true,
				Help: "e.g. https://my123456-api.s4hana.cloud.sap (the API host of the communication arrangement), or your Gateway host. Hosts other than *.s4hana.cloud.sap and *.s4hana.ondemand.com must be listed in saas_upstreams.allowed_hosts."},
			{Key: "auth_type", Label: "Authentication", Type: FieldSelect, Default: "basic", Options: []string{"basic", "oauth_client_credentials"},
				Help: "basic: a communication user (or technical user) and its password. oauth_client_credentials: a client registered for the API, with its token URL."},
			{Key: "username", Label: "User name", Type: FieldText, ShowWhen: showWhen("auth_type", "basic"),
				Help: "The communication user of the arrangement (or a technical user)."},
			{Key: "token_url", Label: "Token URL", Type: FieldText, ShowWhen: showWhen("auth_type", "oauth_client_credentials"),
				Help: "The OAuth token endpoint, e.g. https://my123456-api.s4hana.cloud.sap/sap/bc/sec/oauth2/token or your XSUAA /oauth/token URL."},
			{Key: "client_id", Label: "Client ID", Type: FieldText, ShowWhen: showWhen("auth_type", "oauth_client_credentials"),
				Help: "The OAuth client registered for Fortik."},
			{Key: "scope", Label: "Scope", Type: FieldText, ShowWhen: showWhen("auth_type", "oauth_client_credentials"),
				Help: "Optional scopes to request."},
			{Key: "sap_client", Label: "SAP client", Type: FieldText,
				Help: "Optional three-digit client (sap-client), for on-premise systems with several clients."},
			{Key: "services", Label: "OData services to check", Type: FieldList, Default: []string{"/sap/opu/odata/sap/API_BUSINESS_PARTNER"},
				Help: "Service root paths. Test connection reads each service's $metadata (read-only) and lists its entity sets. Agents may only call paths under /sap/opu/odata/ and /sap/opu/odata4/."},
			{Key: "password", Label: "Password", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_type", "basic"),
				Help: "Required for basic. Stored only in Fortik's secret store."},
			{Key: "client_secret", Label: "Client secret", Type: FieldPassword, Secret: true, ShowWhen: showWhen("auth_type", "oauth_client_credentials"),
				Help: "Required for oauth_client_credentials. Stored only in Fortik's secret store."},
		},
	},
	{
		System: SystemSAPMCP,
		Title:  "SAP MCP server (customer-managed)",
		Fields: append([]Field{
			{Key: "endpoint_url", Label: "MCP server URL", Type: FieldText, Required: true,
				Help: "The Streamable HTTP endpoint of the MCP server you run or license in front of your SAP system. SAP does not publish a native MCP endpoint for S/4HANA that Fortik could verify; the host must be listed in mcp_upstreams.allowed_hosts."},
			{Key: "authorize_url", Label: "Authorization URL", Type: FieldText, ShowWhen: showWhen("auth_type", AuthOAuthCode),
				Help: "The OAuth authorization endpoint of the server's identity provider (authorization code only)."},
			{Key: "token_url", Label: "Token URL", Type: FieldText, ShowWhen: showWhen("auth_type", AuthOAuthCode, AuthClientCreds),
				Help: "The OAuth token endpoint. Its host must be permitted like the server's."},
			{Key: "revoke_url", Label: "Revocation URL", Type: FieldText, ShowWhen: showWhen("auth_type", AuthOAuthCode),
				Help: "Optional. Without it, disconnecting cannot revoke the grant."},
		}, mcpFields([]string{AuthBearer, AuthClientCreds, AuthOAuthCode},
			"Whatever the MCP server you configured requires: a bearer token, OAuth client credentials, or OAuth authorization code.")...),
	},
}
