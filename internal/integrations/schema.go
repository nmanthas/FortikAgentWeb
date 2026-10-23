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
)

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
		fields[i] = f
	}
	s.Fields = fields
	return s
}

// ParseKey validates an integration key ("github", "postgres:acme_prod") and
// returns its system. Errors wrap ErrInvalid.
func ParseKey(key string) (string, error) {
	switch key {
	case SystemGoogle, SystemGitHub, SystemAWS, SystemTemporal, SystemCelery, SystemQueueWebhook:
		return key, nil
	}
	if name, ok := strings.CutPrefix(key, SystemPostgres+":"); ok {
		if !postgresName.MatchString(name) {
			return "", fmt.Errorf("%w: postgres upstream name must match ^[a-z][a-z0-9_]{0,62}$", ErrInvalid)
		}
		return SystemPostgres, nil
	}
	if name, ok := strings.CutPrefix(key, SystemMemory+":"); ok {
		if !postgresName.MatchString(name) {
			return "", fmt.Errorf("%w: memory store name must match ^[a-z][a-z0-9_]{0,62}$", ErrInvalid)
		}
		return SystemMemory, nil
	}
	if key == SystemPostgres || key == SystemMemory {
		return "", fmt.Errorf("%w: %s integrations are keyed %s:<name>", ErrInvalid, key, key)
	}
	return "", fmt.Errorf("%w: unknown integration %q (want google_workspace, github, aws, temporal, celery, queue_webhook, postgres:<name> or memory:<name>)", ErrInvalid, truncate(key, 80))
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
