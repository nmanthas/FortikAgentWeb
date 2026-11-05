package integrations

import (
	"fmt"
	"regexp"
	"strings"
)

// Systems with integration settings.
const (
	SystemGoogle   = "google_workspace"
	SystemGitHub   = "github"
	SystemAWS      = "aws"
	SystemPostgres = "postgres"

	// Queue systems (containment: pause, resume and cancel an agent's
	// queued work; see internal/queues).
	SystemTemporal     = "temporal"
	SystemCelery       = "celery"
	SystemQueueWebhook = "queue_webhook"

	// SystemMemory: agent memory stores (Postgres + pgvector), keyed
	// memory:<name>; see internal/memory.
	SystemMemory = "memory"

	// SystemNotifySlack: a Slack-compatible incoming webhook that receives
	// security alerts and owner notifications (internal/notify).
	SystemNotifySlack = "notify_slack"

	// SystemNetSuite: a NetSuite account reached through Fortik's gateway
	// with OAuth 2.0 client credentials (internal/netsuite).
	SystemNetSuite = "netsuite"

	// SystemNetSuiteQuickStart: the NetSuite QuickStart MCP server, which
	// Fortik connects to over Streamable HTTP with a personal access token
	// (internal/nsquickstart). Transport mcp, business system netsuite.
	SystemNetSuiteQuickStart = "netsuite_quickstart"

	// SystemNetSuiteMCP: a full NetSuite account's MCP server (the NetSuite
	// AI Connector Service), reached with OAuth 2.0 authorization code +
	// PKCE tokens Fortik obtains for a NetSuite user (internal/nsquickstart).
	SystemNetSuiteMCP = "netsuite_mcp"
)

// Providers (applications). A provider's connection types (schemas) are its
// transports; one tenant of a provider is one logical integration.
const (
	ProviderNetSuite = "netsuite"

	// NetSuite environments: a full NetSuite account (SuiteTalk REST web
	// services, the AI Connector Service MCP server) or NetSuite QuickStart
	// (the QuickStart MCP server).
	EnvNetSuiteFull       = "full"
	EnvNetSuiteQuickStart = "quickstart"
)

// connMeta is each connection type's provider, transport and environment.
var connMeta = map[string]struct {
	provider, transport, environment string
	optionalInstance                 bool
}{
	SystemGoogle:             {SystemGoogle, TransportREST, "", false},
	SystemGitHub:             {SystemGitHub, TransportREST, "", false},
	SystemAWS:                {SystemAWS, TransportREST, "", false},
	SystemPostgres:           {SystemPostgres, TransportNative, "", false},
	SystemTemporal:           {SystemTemporal, TransportNative, "", false},
	SystemCelery:             {SystemCelery, TransportNative, "", false},
	SystemQueueWebhook:       {SystemQueueWebhook, TransportREST, "", false},
	SystemMemory:             {SystemMemory, TransportNative, "", false},
	SystemNotifySlack:        {SystemNotifySlack, TransportREST, "", false},
	SystemNetSuite:           {ProviderNetSuite, TransportREST, EnvNetSuiteFull, true},
	SystemNetSuiteQuickStart: {ProviderNetSuite, TransportMCP, EnvNetSuiteQuickStart, true},
	SystemNetSuiteMCP:        {ProviderNetSuite, TransportMCP, EnvNetSuiteFull, true},
	SystemSalesforce:         {ProviderSalesforce, TransportREST, "", true},
	SystemSalesforceMCP:      {ProviderSalesforce, TransportMCP, "", true},
	SystemServiceNow:         {ProviderServiceNow, TransportREST, "", true},
	SystemServiceNowMCP:      {ProviderServiceNow, TransportMCP, "", true},
	SystemSAP:                {ProviderSAP, TransportREST, "", true},
	SystemSAPMCP:             {ProviderSAP, TransportMCP, "", true},
}

// bareKeyTypes are the instance-capable connection types whose bare key is
// a connection of the provider's default tenant (provider:default).
var bareKeyTypes = []string{SystemNetSuite, SystemSalesforce, SystemSalesforceMCP, SystemServiceNow, SystemServiceNowMCP, SystemSAP, SystemSAPMCP}

func init() {
	schemas = append(schemas, saasSchemas...)
	for i := range schemas {
		m, ok := connMeta[schemas[i].System]
		if !ok {
			panic("integrations: no provider/transport for " + schemas[i].System)
		}
		schemas[i].Provider, schemas[i].Transport, schemas[i].Environment, schemas[i].OptionalInstance = m.provider, m.transport, m.environment, m.optionalInstance
	}
}

// QuickStartEndpoint is the documented QuickStart MCP endpoint (Oracle,
// "Set up the QuickStart MCP server").
const QuickStartEndpoint = "https://my.quickstartapi.netsuite.com/mcp"

// Integration statuses (integrations.status).
const (
	StatusUnconfigured = "unconfigured"
	StatusConfigured   = "configured"
	StatusOK           = "ok"
	StatusError        = "error"
)

// postgresName is the <name> in "postgres:<name>" and "memory:<name>"
// (matches the table CHECK).
var postgresName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// schemas is the single source of truth for the fields of each system; the
// console renders its forms from it and validation is driven by it.
var schemas = []Schema{
	{
		System: SystemGoogle,
		Title:  "Google Workspace (Gmail and Drive)",
		Fields: []Field{
			{Key: "primary_domain", Label: "Primary domain", Type: FieldText, Required: true,
				Help: "Your Workspace primary domain, e.g. example.com (Admin console > Account > Domains > Manage domains). Drive shares that policy narrows are rewritten to this domain, and it always counts as internal."},
			{Key: "internal_domains", Label: "Other internal domains", Type: FieldList,
				Help: "Secondary or alias domains that also count as internal for the Gmail recipient and Drive sharing rules, e.g. example.co.uk. One domain per entry."},
			{Key: "test_user", Label: "Test user email", Type: FieldText, Required: true,
				Help: "A user in one of the domains above that \"Test connection\" impersonates (it reads Gmail users.getProfile only). Use a dedicated test account."},
			{Key: "admin_user", Label: "Admin user email (shadow-agent discovery)", Type: FieldText,
				Help: "Optional. A Workspace admin that shadow-agent discovery impersonates to list users' OAuth grants (Admin SDK). Leave empty to use the test user, which must then be an admin. Domain-wide delegation must also allow the scopes admin.directory.user.readonly and admin.directory.user.security."},
			{Key: "service_account_json", Label: "Service account key (JSON)", Type: FieldTextarea, Secret: true, Required: true,
				Help: "Google Cloud console > IAM & Admin > Service accounts > (your account) > Keys > Add key > Create new key > JSON. Paste the whole downloaded file. Then authorise the service account's Client ID in the Admin console > Security > Access and data control > API controls > Manage Domain Wide Delegation, with the Gmail and Drive scopes listed in the Fortik docs."},
		},
	},
	{
		System: SystemGitHub,
		Title:  "GitHub",
		Fields: []Field{
			{Key: "api_base_url", Label: "API base URL", Type: FieldText, Default: "https://api.github.com",
				Help: "Leave as https://api.github.com for github.com. For GitHub Enterprise Server use https://<your-host>/api/v3."},
			{Key: "app_id", Label: "GitHub App ID", Type: FieldText, Required: true,
				Help: "GitHub > Settings > Developer settings > GitHub Apps > (your app) > General > About: the numeric \"App ID\" (not the Client ID)."},
			{Key: "installation_id", Label: "Installation ID", Type: FieldText, Required: true,
				Help: "Install the app on your organisation, then open Organisation settings > GitHub Apps > (your app) > Configure. The installation ID is the number at the end of the page URL: https://github.com/organizations/<org>/settings/installations/<installation id>."},
			{Key: "private_key_pem", Label: "App private key (.pem)", Type: FieldTextarea, Secret: true, Required: true,
				Help: "Your app's settings > General > Private keys > Generate a private key. Paste the entire downloaded .pem file including the BEGIN and END lines. Fortik uses it to sign app JWTs and mint short-lived installation tokens; it never leaves Fortik. For shadow-agent discovery the app also needs the organization permissions \"Personal access tokens\" (read; write to revoke) and \"Administration\" (read)."},
		},
	},
	{
		System: SystemAWS,
		Title:  "AWS",
		Fields: []Field{
			{Key: "region", Label: "Region", Type: FieldText, Required: true,
				Help: "Region used for STS calls and as the agents' default, e.g. us-east-1."},
			{Key: "role_arn", Label: "Agent role ARN", Type: FieldText, Required: true,
				Help: "The IAM role Fortik assumes on behalf of agents, e.g. arn:aws:iam::123456789012:role/fortik-agents (IAM > Roles > (role) > ARN). Its trust policy must let Fortik's IAM user call sts:AssumeRole and sts:SetSourceIdentity. Fortik attaches an inline policy named fortik-revocations to it to revoke agents."},
			{Key: "sts_endpoint", Label: "STS endpoint override", Type: FieldText,
				Help: "Leave empty to use AWS. Only for testing against a local STS emulator."},
			{Key: "iam_endpoint", Label: "IAM endpoint override", Type: FieldText,
				Help: "Leave empty to use AWS. Only for testing against a local IAM emulator."},
			{Key: "access_key_id", Label: "Fortik access key ID", Type: FieldPassword, Secret: true, Required: true,
				Help: "Access key of the IAM user Fortik itself uses (IAM > Users > (user) > Security credentials > Create access key). Grant it only sts:AssumeRole on the role above and iam:PutRolePolicy and iam:GetRolePolicy on that role. For shadow-agent discovery also grant iam:ListUsers, iam:ListAccessKeys and iam:GetAccessKeyLastUsed (and iam:UpdateAccessKey to let Fortik deactivate a flagged key)."},
			{Key: "secret_access_key", Label: "Fortik secret access key", Type: FieldPassword, Secret: true, Required: true,
				Help: "Shown once by AWS when the access key is created."},
			{Key: "external_id", Label: "External ID", Type: FieldPassword, Secret: true,
				Help: "Only if the role's trust policy requires sts:ExternalId. Send null to remove a stored value."},
		},
	},
	{
		System: SystemPostgres,
		Title:  "PostgreSQL upstream",
		Multi:  true,
		Fields: []Field{
			{Key: "host", Label: "Host", Type: FieldText, Required: true,
				Help: "Hostname or IP address of the database server agents reach through Fortik's proxy."},
			{Key: "port", Label: "Port", Type: FieldNumber, Default: 5432,
				Help: "TCP port, usually 5432."},
			{Key: "database", Label: "Database", Type: FieldText, Required: true,
				Help: "Database name on the server. Agents connect to Fortik's proxy using the upstream name (the part after \"postgres:\")."},
			{Key: "sslmode", Label: "TLS mode", Type: FieldSelect, Default: "require",
				Options: []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"},
				Help:    "Use verify-full in production. \"disable\" is only for local test databases."},
			{Key: "environment", Label: "Environment", Type: FieldSelect, Required: true,
				Options: []string{"prod", "staging", "dev"},
				Help:    "Policy input: production databases get the strictest rules."},
			{Key: "admin_user", Label: "Admin role", Type: FieldText, Required: true,
				Help: "A role with CREATEROLE (not a superuser) that may grant read_role and write_role. Fortik uses it only to create, rotate and disable per-agent login roles (fortik_a_<agent>)."},
			{Key: "read_role", Label: "Read group role", Type: FieldText, Required: true,
				Help: "An existing NOLOGIN role holding the read grants (e.g. GRANT SELECT ON ALL TABLES IN SCHEMA public). Agents with read_only access become members of it."},
			{Key: "write_role", Label: "Write group role", Type: FieldText, Required: true,
				Help: "An existing NOLOGIN role holding the read and write grants. Agents with read_write access become members of it."},
			{Key: "admin_password", Label: "Admin role password", Type: FieldPassword, Secret: true, Required: true,
				Help: "Password of the admin role above. Stored only in the secret store."},
		},
	},
	{
		System: SystemTemporal,
		Title:  "Temporal (queued workflows)",
		Fields: []Field{
			{Key: "host_port", Label: "Frontend address", Type: FieldText, Required: true,
				Help: "host:port of the Temporal frontend gRPC service, e.g. temporal.internal:7233, or <namespace>.<account>.tmprl.cloud:7233 for Temporal Cloud."},
			{Key: "namespace", Label: "Namespace", Type: FieldText, Default: "default",
				Help: "The namespace your agents' workflows run in. Register the Keyword search attribute FortikAgentId there (temporal operator search-attribute create --name FortikAgentId --type Keyword) and set it on every workflow and schedule an agent starts; Fortik pauses, resumes and cancels work by that tag."},
			{Key: "tls", Label: "Use TLS", Type: FieldBool, Default: false,
				Help: "Required for Temporal Cloud and whenever an API key is set (the key is never sent over plaintext)."},
			{Key: "api_key", Label: "API key", Type: FieldPassword, Secret: true,
				Help: "Temporal Cloud > Settings > API keys (a service account key with write access to the namespace). Leave empty for a self-hosted cluster without authentication. Send null to remove a stored value."},
		},
	},
	{
		System: SystemCelery,
		Title:  "Celery (Redis broker)",
		Fields: []Field{
			{Key: "queues", Label: "Queues", Type: FieldList, Default: []string{"celery"},
				Help: "Names of the Celery queues agents' tasks are sent to (Celery's default queue is \"celery\"). Producers must set the message header fortik_agent_id, e.g. task.apply_async(args, headers={\"fortik_agent_id\": \"<agent id>\"}). Priority sub-queues are covered automatically."},
			{Key: "redis_url", Label: "Broker URL", Type: FieldPassword, Secret: true, Required: true,
				Help: "The broker_url of your Celery app: redis://[:password@]host:6379/0, or rediss:// for TLS. Fortik moves only messages tagged with the agent's id and publishes revoke broadcasts on the same database."},
		},
	},
	{
		System: SystemQueueWebhook,
		Title:  "Queue control webhook",
		Fields: []Field{
			{Key: "url", Label: "Webhook URL", Type: FieldText, Required: true,
				Help: "Your endpoint that pauses, resumes or cancels an agent's queued jobs in any other job system. Fortik POSTs JSON {\"action\": \"pause\"|\"resume\"|\"cancel\"|\"test\", \"agent_id\", \"reason\", \"ts\"} and treats any 2xx reply as done. Redirects are not followed."},
			{Key: "secret", Label: "Signing secret", Type: FieldPassword, Secret: true, Required: true,
				Help: "At least 16 random characters shared with your endpoint. Every request carries X-Fortik-Signature: sha256=<hex HMAC-SHA256 of the raw body with this secret>; reject requests whose signature does not match."},
		},
	},
	{
		System: SystemNetSuite,
		Title:  "NetSuite REST API (SuiteTalk)",
		Fields: []Field{
			{Key: "account_id", Label: "Account ID", Type: FieldText, Required: true,
				Help: "Your NetSuite account ID as shown in Setup > Company > Company Information (e.g. 1234567, or 1234567_SB1 for a sandbox). Use a sandbox or test account."},
			{Key: "client_id", Label: "Client ID", Type: FieldText, Required: true,
				Help: "From the integration record you create for Fortik (Setup > Integration > Manage Integrations) with the client credentials (machine to machine) grant and the REST web services scope enabled."},
			{Key: "certificate_id", Label: "Certificate ID", Type: FieldText, Required: true,
				Help: "After uploading Fortik's public certificate in the OAuth 2.0 client credentials (M2M) setup and mapping it to the integration, an entity and a role, NetSuite shows a certificate ID. The role decides everything Fortik (and agents through it) can do: give it least privilege."},
			{Key: "algorithm", Label: "Signing algorithm", Type: FieldSelect, Default: "PS256", Options: []string{"PS256", "ES256"},
				Help: "PS256 for an RSA key (3072 bits or more recommended), ES256 for an EC P-256 key. It must match the key below."},
			{Key: "scope", Label: "Scope", Type: FieldText, Default: "rest_webservices",
				Help: "OAuth scope requested in the token assertion. rest_webservices is what the gateway and SuiteQL use."},
			{Key: "agent_map", Label: "Agents", Type: FieldList,
				Help: "One entry per agent that works in this account: fortik_agent_id=netsuite_entity_internal_id (the employee or entity the agent's own NetSuite activity is recorded under). Used to attribute audit records to agents; unmapped activity is not attributed to any agent."},
			{Key: "activity_query", Label: "Activity query (SuiteQL)", Type: FieldTextarea,
				Help: "Optional. Overrides the SuiteQL query Fortik uses to read record changes (system notes). Leave empty for the default; Test connection reports whether the default works in your account."},
			{Key: "api_base", Label: "API base URL (advanced)", Type: FieldText,
				Help: "Optional. Leave empty to use https://<account>.suitetalk.api.netsuite.com. Only for test endpoints."},
			{Key: "private_key_pem", Label: "Private key (PEM)", Type: FieldTextarea, Secret: true, Required: true,
				Help: "The private key of the certificate uploaded to NetSuite (PKCS#8, or PKCS#1 RSA / SEC1 EC). It never leaves Fortik; agents never receive NetSuite credentials."},
		},
	},
	{
		System: SystemNetSuiteQuickStart,
		Title:  "NetSuite QuickStart MCP server",
		Fields: []Field{
			{Key: "name", Label: "Integration name", Type: FieldText, Default: "NetSuite QuickStart",
				Help: "A name for this connection, shown in the console and the Diary."},
			{Key: "tenant_label", Label: "QuickStart account / tenant label", Type: FieldText, Required: true,
				Help: "How your team refers to this QuickStart company (e.g. \"Acme test company\"). A label only: QuickStart identifies the company from the token."},
			{Key: "endpoint_url", Label: "MCP endpoint URL", Type: FieldText, Default: QuickStartEndpoint,
				Help: "Leave as " + QuickStartEndpoint + " (Oracle's documented endpoint). Fortik connects only to hosts allowed in its configuration (mcp_upstreams.allowed_hosts), so a changed URL to any other host is refused at connection time."},
			{Key: "transport", Label: "Transport", Type: FieldSelect, Default: "streamable_http", Options: []string{"streamable_http"},
				Help: "QuickStart's MCP server uses Streamable HTTP."},
			{Key: "auth_type", Label: "Authentication", Type: FieldSelect, Default: "personal_access_token", Options: []string{"personal_access_token"},
				Help: "A QuickStart personal access token, sent upstream as Authorization: Bearer <token> by Fortik only."},
			{Key: "token_expires_on", Label: "Token expiration date", Type: FieldText,
				Help: "Optional, YYYY-MM-DD as shown when you created the token (default 30 days after creation). Fortik cannot read it from QuickStart; it uses it to warn before the token stops working."},
			{Key: "personal_access_token", Label: "Personal access token", Type: FieldPassword, Secret: true, Required: true,
				Help: "QuickStart: Menu > Administration > QuickStart settings > Personal access tokens > create a token named Fortik (keep the default read-only scope), then Copy token. It is shown only once. Paste only the token, without \"Bearer\". It acts with the QuickStart permissions of the user who created it; it is stored only in Fortik's secret store and never sent to agents or the browser."},
		},
	},
	{
		System: SystemNetSuiteMCP,
		Title:  "NetSuite MCP server (AI Connector Service)",
		Fields: []Field{
			{Key: "account_id", Label: "Account ID", Type: FieldText, Required: true,
				Help: "Your NetSuite account ID (Setup > Company > Company Information), e.g. 1234567 or 1234567_SB1. It must be the same account as this integration's REST connection, if any. Fortik derives the MCP, token and authorization endpoints from it."},
			{Key: "client_id", Label: "Client ID", Type: FieldText, Required: true,
				Help: "From the integration record for the NetSuite AI Connector Service (Setup > Integration > Manage Integrations): Public Client checked, Authorization Code Grant checked, the NetSuite AI Connector Service scope enabled, and Fortik's redirect URI below entered as a Redirect URI."},
			{Key: "redirect_uri", Label: "Redirect URI", Type: FieldText, Default: "http://127.0.0.1:8080/v1/oauth/netsuite/callback",
				Help: "Fortik's OAuth callback (the address you open the Fortik console at, followed by /v1/oauth/netsuite/callback). It must match a Redirect URI on the integration record exactly."},
			{Key: "scope", Label: "Scope", Type: FieldText, Default: "mcp",
				Help: "The OAuth scope value for the NetSuite AI Connector Service. Oracle's documentation names the scope in the integration record UI but not its value; third-party guides use mcp. Check your integration record."},
			{Key: "tools_path", Label: "Tools", Type: FieldSelect, Default: "all", Options: []string{"all", "suiteapp/com.netsuite.mcpstandardtools"},
				Help: "all: every custom tool in the account (…/services/mcp/v1/all). suiteapp/com.netsuite.mcpstandardtools: only the MCP Standard Tools SuiteApp's tools."},
			{Key: "api_base", Label: "API base URL (advanced)", Type: FieldText,
				Help: "Optional. Leave empty to use https://<account>.suitetalk.api.netsuite.com (and https://<account>.app.netsuite.com for authorization). Only for test endpoints."},
			{Key: "oauth_tokens", Label: "OAuth tokens", Type: FieldPassword, Secret: true, Managed: true,
				Help: "Obtained by Fortik when a NetSuite user authorizes this connection (Authorize). Never entered by hand."},
		},
	},
	{
		System: SystemNotifySlack,
		Title:  "Slack notifications",
		Fields: []Field{
			{Key: "webhook_url", Label: "Incoming webhook URL", Type: FieldPassword, Secret: true, Required: true,
				Help: "Slack: Apps > Incoming Webhooks > Add to a channel, then copy the https://hooks.slack.com/services/... URL. Anyone with this URL can post to the channel, so it is stored only in the secret store. Fortik POSTs {\"text\": ...} for each alert: its severity, kind, summary, the agent and the agent's owner."},
			{Key: "min_severity", Label: "Minimum severity", Type: FieldSelect, Default: "info", Options: []string{"info", "warning", "high", "critical"},
				Help: "Alerts below this severity are not posted. \"info\" includes the owner notification that a timed suspension was restored."},
			{Key: "kinds", Label: "Only these alert kinds", Type: FieldList,
				Help: "Optional. Leave empty to post every kind, e.g. override_restored, override_restore_blocked, delegation_bypass, swarm_detected, shadow_agent, hidden_signal."},
			{Key: "console_url", Label: "Console URL", Type: FieldText,
				Help: "Optional. The address people open the Fortik console at (e.g. https://fortik.example.com). Messages then link to the agent."},
		},
	},
	{
		System: SystemMemory,
		Title:  "Agent memory store (PostgreSQL + pgvector)",
		Multi:  true,
		Fields: []Field{
			{Key: "host", Label: "Host", Type: FieldText, Required: true,
				Help: "Hostname or IP address of the PostgreSQL server that holds agent memory. The data stays in this database; Fortik keeps pointers only."},
			{Key: "port", Label: "Port", Type: FieldNumber, Default: 5432,
				Help: "TCP port, usually 5432."},
			{Key: "database", Label: "Database", Type: FieldText, Required: true,
				Help: "Database name. Fortik creates schema fortik_memory in it (items table and snapshot tables)."},
			{Key: "sslmode", Label: "TLS mode", Type: FieldSelect, Default: "require",
				Options: []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"},
				Help:    "Use verify-full in production. \"disable\" is only for local test databases."},
			{Key: "dimension", Label: "Embedding dimension", Type: FieldNumber,
				Help: "Optional. Size of the embedding vectors (e.g. 1536). Leave empty to size the column from the first embedding written."},
			{Key: "admin_user", Label: "Admin role", Type: FieldText, Required: true,
				Help: "A role that owns schema fortik_memory (or may create it: CREATE on the database). The vector extension must be installed (CREATE EXTENSION vector) or this role must be allowed to install it. Agents never receive these credentials."},
			{Key: "admin_password", Label: "Admin role password", Type: FieldPassword, Secret: true, Required: true,
				Help: "Password of the admin role above. Stored only in the secret store."},
		},
	},
}

// Schemas returns the field definitions for every integration type (a copy;
// callers may not modify the package's definitions).
func Schemas() []Schema {
	out := make([]Schema, len(schemas))
	for i, s := range schemas {
		out[i] = copySchema(s)
	}
	return out
}

// SchemaFor returns the schema for one system.
func SchemaFor(system string) (Schema, bool) {
	for _, s := range schemas {
		if s.System == system {
			return copySchema(s), true
		}
	}
	return Schema{}, false
}

func copySchema(s Schema) Schema {
	fields := make([]Field, len(s.Fields))
	for i, f := range s.Fields {
		f.Options = append([]string(nil), f.Options...)
		if d, ok := f.Default.([]string); ok {
			f.Default = append([]string(nil), d...)
		}
		if f.ShowWhen != nil {
			sw := make(map[string][]string, len(f.ShowWhen))
			for k, v := range f.ShowWhen {
				sw[k] = append([]string(nil), v...)
			}
			f.ShowWhen = sw
		}
		fields[i] = f
	}
	s.Fields = fields
	return s
}

// ParseKey validates an integration (connection) key and returns its
// system: "github", "postgres:acme_prod", "netsuite" (the legacy
// single NetSuite REST connection) or "netsuite:acme". Errors wrap
// ErrInvalid.
func ParseKey(key string) (string, error) {
	switch key {
	case SystemGoogle, SystemGitHub, SystemAWS, SystemTemporal, SystemCelery, SystemQueueWebhook, SystemNotifySlack, SystemNetSuiteQuickStart:
		return key, nil
	}
	if slicesContains(bareKeyTypes, key) {
		return key, nil
	}
	system, name, ok := strings.Cut(key, ":")
	if ok {
		switch system {
		case SystemPostgres, SystemMemory, SystemNetSuite, SystemNetSuiteQuickStart, SystemNetSuiteMCP,
			SystemSalesforce, SystemSalesforceMCP, SystemServiceNow, SystemServiceNowMCP, SystemSAP, SystemSAPMCP:
			if !postgresName.MatchString(name) {
				return "", fmt.Errorf("%w: the name after %q must match ^[a-z][a-z0-9_]{0,62}$", ErrInvalid, system+":")
			}
			return system, nil
		}
	}
	if key == SystemPostgres || key == SystemMemory || key == SystemNetSuiteMCP {
		return "", fmt.Errorf("%w: %s integrations are keyed %s:<name>", ErrInvalid, key, key)
	}
	return "", fmt.Errorf("%w: unknown integration %q (want google_workspace, github, aws, temporal, celery, queue_webhook, notify_slack, netsuite[:<tenant>], netsuite_quickstart[:<tenant>], netsuite_mcp:<tenant>, salesforce[_mcp][:<tenant>], servicenow[_mcp][:<tenant>], sap[_mcp][:<tenant>], postgres:<name> or memory:<name>)", ErrInvalid, truncate(key, 80))
}

// LogicalID is the logical application integration a connection key
// belongs to: provider:instance (netsuite_mcp:acme -> netsuite:acme), or,
// for single-instance keys, provider:default (github -> github:default)
// and netsuite:quickstart for the legacy QuickStart connection. Migration
// 0018 derives the same ids.
func LogicalID(key string) (provider, id string, err error) {
	system, err := ParseKey(key)
	if err != nil {
		return "", "", err
	}
	m := connMeta[system]
	_, name, ok := strings.Cut(key, ":")
	if !ok {
		name = "default"
		if system == SystemNetSuiteQuickStart {
			name = "quickstart"
		}
	}
	return m.provider, m.provider + ":" + name, nil
}

// ConnectionKey is the key of the connection of the given type for a
// logical integration: the inverse of LogicalID (legacy single keys are
// returned for their logical ids).
func ConnectionKey(system, integrationID string) (string, error) {
	m, ok := connMeta[system]
	if !ok {
		return "", fmt.Errorf("%w: unknown connection type %q", ErrInvalid, truncate(system, 64))
	}
	provider, name, ok := strings.Cut(integrationID, ":")
	if !ok || provider != m.provider || !postgresName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a %s integration id", ErrInvalid, truncate(integrationID, 80), m.provider)
	}
	switch {
	case system == SystemNetSuiteQuickStart && name == "quickstart", slicesContains(bareKeyTypes, system) && name == "default":
		return system, nil
	case !m.optionalInstance && !slicesContains([]string{SystemPostgres, SystemMemory}, system):
		if name != "default" {
			return "", fmt.Errorf("%w: %s has a single connection (integration %s:default)", ErrInvalid, system, m.provider)
		}
		return system, nil
	}
	return system + ":" + name, nil
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// SecretName is the secret-store name for one secret field of an
// integration: integration/<system>/<field>, or for Postgres upstreams
// integration/postgres/<name>/<field> (':' is not allowed in secret names).
func SecretName(key, field string) string {
	return "integration/" + strings.Replace(key, ":", "/", 1) + "/" + field
}

func secretFieldNames(s Schema) []string {
	var out []string
	for _, f := range s.Fields {
		if f.Secret {
			out = append(out, f.Key)
		}
	}
	return out
}

func fieldByKey(s Schema, key string) (Field, bool) {
	for _, f := range s.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "..."
}
