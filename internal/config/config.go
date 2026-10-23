// Package config loads fortik.yaml. Secrets are never stored in the config
// file: fields ending in _secret name an entry in the secret provider.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL string        `yaml:"database_url"` // Fortik's own system of record (not a customer DB)
	API         APIConfig     `yaml:"api"`
	Policy      PolicyConfig  `yaml:"policy"`
	Diary       DiaryConfig   `yaml:"diary"`
	Secrets     SecretsConfig `yaml:"secrets"`
	Fail        FailConfig    `yaml:"fail"`
	PGProxy     PGProxyConfig `yaml:"pgproxy"`
	Undo        UndoConfig    `yaml:"undo"`
	LogLevel    string        `yaml:"log_level"`

	// Phase 2
	Gateway GatewayConfig `yaml:"gateway"`
	Broker  BrokerConfig  `yaml:"broker"`
	Auth    AuthConfig    `yaml:"auth"`
	Events  EventsConfig  `yaml:"events"`
	Ladder  LadderConfig  `yaml:"ladder"`
	Console ConsoleConfig `yaml:"console"`

	// Phase 3
	Delegation DelegationConfig `yaml:"delegation"`
	Population PopulationConfig `yaml:"population"`
	Counters   CountersConfig   `yaml:"counters"`
	Approvals  ApprovalsConfig  `yaml:"approvals"`
	Overrides  OverridesConfig  `yaml:"overrides"`
	AgentGW    AgentGWConfig    `yaml:"agentgw"`
	Hook       HookConfig       `yaml:"hook"`

	// Phase 4
	Memory    MemoryConfig    `yaml:"memory"`
	Retention RetentionConfig `yaml:"retention"`

	// Phase 5
	Swarm    SwarmConfig    `yaml:"swarm"`
	Map      MapConfig      `yaml:"map"`
	Shadow   ShadowConfig   `yaml:"shadow"`
	Baseline BaselineConfig `yaml:"baseline"`
}

// SwarmConfig: swarm detection and the Max-5 breaker.
type SwarmConfig struct {
	BreakerN       int           `yaml:"breaker_n"`       // plan: 5 distinct agents/copies; the next match trips
	BreakerWindow  time.Duration `yaml:"breaker_window"`  // default 10m
	FanoutLimit    int           `yaml:"fanout_limit"`    // children one root may spawn in the window (default 10)
	DepthLimit     int           `yaml:"depth_limit"`     // delegation depth (default delegation.max_depth)
	ConvergeN      int           `yaml:"converge_n"`      // distinct agents hitting one target in the window (default 8)
	ConvergeWindow time.Duration `yaml:"converge_window"` // default 10m
	SweepInterval  time.Duration `yaml:"sweep_interval"`  // background detection pass (default 15s)
}

// MapConfig: the communication map.
type MapConfig struct {
	Window          time.Duration `yaml:"window"`            // plan: 5m rollup windows
	RollupInterval  time.Duration `yaml:"rollup_interval"`   // default 10s
	Retention       time.Duration `yaml:"retention"`         // edges kept for replay (default 30 days)
	EncodedParamMin int           `yaml:"encoded_param_min"` // hidden signal: encoded URL parameter size threshold (default 256 bytes)
}

// ShadowConfig: shadow-agent discovery.
type ShadowConfig struct {
	SweepInterval        time.Duration `yaml:"sweep_interval"`         // default 15m; 0 = manual only
	PostgresExcludeRoles []string      `yaml:"postgres_exclude_roles"` // roles that are not shadow agents (people, known services)
	GitHubKnownApps      []string      `yaml:"github_known_apps"`      // app slugs installed on purpose
}

// BaselineConfig: 14-day hourly baselines per agent and verb (no ML).
type BaselineConfig struct {
	Days           int     `yaml:"days"`             // plan: 14
	Sigma          float64 `yaml:"sigma"`            // plan: mean + 3 sigma
	MedianFactor   float64 `yaml:"median_factor"`    // plan: 5x median when history < MinHistoryDays
	MinHistoryDays int     `yaml:"min_history_days"` // plan: 3
	MinCount       int64   `yaml:"min_count"`        // never "above normal" below this hourly count (default 20)
	// FirstUseCeiling bounds an hour with no usable history (a verb the agent
	// never used, or fewer than MinActiveHours active hours): above it the
	// hour is above normal (default 200).
	FirstUseCeiling int64 `yaml:"first_use_ceiling"`
	MinActiveHours  int   `yaml:"min_active_hours"` // active hours before the agent's own median is trusted alone (default 6)
}

// MemoryConfig: memory gateway, staging and snapshots.
type MemoryConfig struct {
	PromotionDelay    time.Duration `yaml:"promotion_delay"`    // plan: 10m
	PromotionPoll     time.Duration `yaml:"promotion_poll"`     // default 30s
	SnapshotEvery     time.Duration `yaml:"snapshot_every"`     // automatic clean snapshots (default 1h; 0 = manual only)
	SnapshotRetention time.Duration `yaml:"snapshot_retention"` // plan: 30 days
}

// RetentionConfig: purge of undo snapshots (30d), trash tables (7d) and
// memory snapshots, run by a worker against the customer's stores.
type RetentionConfig struct {
	SweepInterval time.Duration `yaml:"sweep_interval"` // default 1h
}

// DelegationConfig: agent-to-agent delegation chains.
type DelegationConfig struct {
	SigningKeySecret string        `yaml:"signing_key_secret"` // HMAC key (auto-created if missing)
	TokenTTL         time.Duration `yaml:"token_ttl"`          // default 15m
	MaxDepth         int           `yaml:"max_depth"`          // default 5
	// BypassOriginLevel: where the ORIGINATING agent is stepped down when a
	// delegated action violates its permissions (default SUPERVISED).
	BypassOriginLevel string `yaml:"bypass_origin_level"`
}

// PopulationConfig: copies, spawn spikes, rate limits.
type PopulationConfig struct {
	HeartbeatInterval       time.Duration `yaml:"heartbeat_interval"`          // default 15s (plan)
	StaleAfter              time.Duration `yaml:"stale_after"`                 // default 45s
	SpikeCooldown           time.Duration `yaml:"spike_cooldown"`              // throttle window after a spike (default 5m)
	DefaultActionRatePerMin int           `yaml:"default_action_rate_per_min"` // 0 = unlimited
}

// CountersConfig: hot counters (rate limits, spawn rates). Redis per plan;
// memory is single-process only (dev/tests).
type CountersConfig struct {
	Provider string `yaml:"provider"` // memory | redis (default memory)
	RedisURL string `yaml:"redis_url"`
}

type ApprovalsConfig struct {
	GrantTTL time.Duration `yaml:"grant_ttl"` // default 15m
	// AllowTokenPairs lets two API tokens supply both votes of a two-person
	// rule (a hold needing two approvers, a swarm release). Default false:
	// one operator holding two tokens could otherwise approve alone, so at
	// most one vote may come from a token and the other from a signed-in
	// person. Meant for single-operator dev/demo setups only.
	AllowTokenPairs bool `yaml:"allow_token_pairs"`
	// AllowOwnerApproval lets an agent's sponsor approve its own agent's held
	// actions (default false: separation of duties).
	AllowOwnerApproval bool `yaml:"allow_owner_approval"`
}

type OverridesConfig struct {
	SweepInterval time.Duration `yaml:"sweep_interval"` // restore worker (default 5s)
}

// AgentGWConfig: Fortik's callout service for agentgateway (MCP, A2A, HTTP egress).
type AgentGWConfig struct {
	Enabled       bool              `yaml:"enabled"`
	Listen        string            `yaml:"listen"`         // gRPC, default 127.0.0.1:9091
	A2ATargets    map[string]string `yaml:"a2a_targets"`    // route/host -> target agent id
	MCPServers    map[string]string `yaml:"mcp_servers"`    // route/host -> MCP server name
	InternalHosts []string          `yaml:"internal_hosts"` // hosts considered inside the company
}

// HookConfig: Claude Code / coding-agent hook endpoint behaviour.
type HookConfig struct {
	ProxyHosts []string `yaml:"proxy_hosts"` // DB hosts that ARE the Fortik proxy (direct DB access elsewhere is a bypass)
}

// GatewayConfig: the agent-facing app gateway (/gw/*, /v1/credentials/issue).
type GatewayConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"` // default 127.0.0.1:8090
	// Overrides for upstream base URLs (tests point these at local fakes).
	GoogleTokenURL  string        `yaml:"google_token_url"`
	GmailBaseURL    string        `yaml:"gmail_base_url"`
	DriveBaseURL    string        `yaml:"drive_base_url"`
	DriveUploadURL  string        `yaml:"drive_upload_url"`
	MaxBodyBytes    int64         `yaml:"max_body_bytes"`    // default 25 MiB
	DelayedSendPoll time.Duration `yaml:"delayed_send_poll"` // default 1s
}

// BrokerConfig: credential lifetimes.
type BrokerConfig struct {
	AWSSessionTTL      time.Duration `yaml:"aws_session_ttl"`      // default 15m (plan)
	PostgresSessionTTL time.Duration `yaml:"postgres_session_ttl"` // default 15m
}

// AuthConfig: human login for the console.
type AuthConfig struct {
	OIDC           OIDCConfig     `yaml:"oidc"`
	DevLogin       DevLoginConfig `yaml:"dev_login"`
	SessionTTL     time.Duration  `yaml:"session_ttl"`      // default 12h absolute
	SessionIdleTTL time.Duration  `yaml:"session_idle_ttl"` // default 1h
}

type OIDCConfig struct {
	Issuer             string              `yaml:"issuer"`
	ClientID           string              `yaml:"client_id"`
	ClientSecretSecret string              `yaml:"client_secret_secret"` // name in the secret store
	RedirectURL        string              `yaml:"redirect_url"`
	RoleClaim          string              `yaml:"role_claim"` // e.g. "groups"
	RoleMap            map[string][]string `yaml:"role_map"`   // claim value -> fortik roles
	EmailRoles         map[string][]string `yaml:"email_roles"`
}

// DevLoginConfig: local development only; refused unless the API listens on loopback.
type DevLoginConfig struct {
	Enabled bool           `yaml:"enabled"`
	Users   []DevLoginUser `yaml:"users"`
}

type DevLoginUser struct {
	Email string   `yaml:"email"`
	Name  string   `yaml:"name"`
	Roles []string `yaml:"roles"`
}

type EventsConfig struct {
	Provider string `yaml:"provider"` // memory | nats (default memory)
	URL      string `yaml:"url"`      // nats://127.0.0.1:4222
}

type LadderConfig struct {
	YellowHoldsThreshold int           `yaml:"yellow_holds_threshold"` // default 3 (plan)
	YellowWindow         time.Duration `yaml:"yellow_window"`          // default 10m (plan)
}

type ConsoleConfig struct {
	Enabled bool `yaml:"enabled"` // serve the embedded SPA at /
}

type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	// TokensSecret names a secret holding JSON: [{"name","sha256","roles":[...]}].
	// Phase 1 service/operator authentication; OIDC for humans arrives with the console.
	TokensSecret string `yaml:"tokens_secret"`
	// AllowedHosts are extra Host header names the API accepts (DNS
	// rebinding defence). On a loopback listener 127.0.0.1/localhost/[::1]
	// are always allowed; elsewhere, set it to the console's public name(s).
	AllowedHosts []string `yaml:"allowed_hosts"`
}

type PolicyConfig struct {
	Dir       string        `yaml:"dir"`
	HotReload bool          `yaml:"hot_reload"`
	PollEvery time.Duration `yaml:"poll_every"`
}

type DiaryConfig struct {
	// SigningKeySecret names a secret holding a base64 Ed25519 seed (32 bytes)
	// used to sign exported/sealed root hashes.
	SigningKeySecret string `yaml:"signing_key_secret"`
	// RetiredPublicKeys (base64 Ed25519) still verify roots sealed before a key rotation.
	RetiredPublicKeys []string `yaml:"retired_public_keys"`
}

type SecretsConfig struct {
	Provider string `yaml:"provider"` // "encfile" (dev/pilot default) | "vault" | "file" (read-only) | "env" (read-only)
	Dir      string `yaml:"dir"`
	// encfile: 32-byte key, base64, from env FORTIK_MASTER_KEY or this file.
	MasterKeyFile string `yaml:"master_key_file"`
	// vault (KV v2; OpenBao compatible). Token from env VAULT_TOKEN.
	VaultAddr   string `yaml:"vault_addr"`
	VaultMount  string `yaml:"vault_mount"`  // default "secret"
	VaultPrefix string `yaml:"vault_prefix"` // default "fortik/"
}

// FailConfig: when Decide cannot reach control state or evaluate policy, every
// call fails closed except READs explicitly allowlisted here.
type FailConfig struct {
	GreenReadAllowlist []FailOpenEntry `yaml:"green_read_allowlist"`
}

type FailOpenEntry struct {
	System string `yaml:"system"`
	Agent  string `yaml:"agent"` // exact agent_id or "*"
}

type PGProxyConfig struct {
	Enabled           bool                      `yaml:"enabled"`
	Listen            string                    `yaml:"listen"`
	AgentTokensSecret string                    `yaml:"agent_tokens_secret"` // JSON {"agent_id":"<sha256 hex of token>"}
	TLSCertFile       string                    `yaml:"tls_cert_file"`
	TLSKeyFile        string                    `yaml:"tls_key_file"`
	Upstreams         map[string]UpstreamConfig `yaml:"upstreams"` // key = database name the agent connects to
	DataLabels        []DataLabelRule           `yaml:"data_labels"`
	PreQueryTimeout   time.Duration             `yaml:"pre_query_timeout"`
}

type UpstreamConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Database       string `yaml:"database"`
	User           string `yaml:"user"`
	PasswordSecret string `yaml:"password_secret"`
	SSLMode        string `yaml:"sslmode"`
	Environment    string `yaml:"environment"` // prod | staging | dev — policy input
}

// DataLabelRule attaches data labels (e.g. customer_pii) to tables.
// Match is "schema.table", "schema.*" or "*.table".
type DataLabelRule struct {
	Match  string   `yaml:"match"`
	Labels []string `yaml:"labels"`
}

type UndoConfig struct {
	SnapshotRetention time.Duration `yaml:"snapshot_retention"` // plan: 30 days
	TrashRetention    time.Duration `yaml:"trash_retention"`    // plan: 7 days
}

// Load reads a YAML config, expands ${ENV} references and applies defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.Expand(string(raw), func(k string) string { return os.Getenv(k) })
	c := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if v := os.Getenv("FORTIK_DATABASE_URL"); v != "" {
		c.DatabaseURL = v
	}
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:8080"
	}
	if c.API.TokensSecret == "" {
		c.API.TokensSecret = "api_tokens"
	}
	if c.Policy.Dir == "" {
		c.Policy.Dir = "policies"
	}
	if c.Policy.PollEvery == 0 {
		c.Policy.PollEvery = 2 * time.Second
	}
	if c.Diary.SigningKeySecret == "" {
		c.Diary.SigningKeySecret = "diary_signing_key"
	}
	if c.Secrets.Provider == "" {
		c.Secrets.Provider = "file"
	}
	if c.PGProxy.Listen == "" {
		c.PGProxy.Listen = "127.0.0.1:6432"
	}
	if c.PGProxy.AgentTokensSecret == "" {
		c.PGProxy.AgentTokensSecret = "agent_tokens"
	}
	if c.PGProxy.PreQueryTimeout == 0 {
		c.PGProxy.PreQueryTimeout = 3 * time.Second
	}
	for k, u := range c.PGProxy.Upstreams {
		if u.Port == 0 {
			u.Port = 5432
		}
		if u.Database == "" {
			u.Database = k
		}
		if u.SSLMode == "" {
			u.SSLMode = "prefer"
		}
		c.PGProxy.Upstreams[k] = u
	}
	if c.Undo.SnapshotRetention == 0 {
		c.Undo.SnapshotRetention = 30 * 24 * time.Hour
	}
	if c.Undo.TrashRetention == 0 {
		c.Undo.TrashRetention = 7 * 24 * time.Hour
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Gateway.Listen == "" {
		c.Gateway.Listen = "127.0.0.1:8090"
	}
	if c.Gateway.MaxBodyBytes == 0 {
		c.Gateway.MaxBodyBytes = 25 << 20
	}
	if c.Gateway.DelayedSendPoll == 0 {
		c.Gateway.DelayedSendPoll = time.Second
	}
	if c.Broker.AWSSessionTTL == 0 {
		c.Broker.AWSSessionTTL = 15 * time.Minute
	}
	if c.Broker.PostgresSessionTTL == 0 {
		c.Broker.PostgresSessionTTL = 15 * time.Minute
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = 12 * time.Hour
	}
	if c.Auth.SessionIdleTTL == 0 {
		c.Auth.SessionIdleTTL = time.Hour
	}
	if c.Events.Provider == "" {
		c.Events.Provider = "memory"
	}
	if c.Ladder.YellowHoldsThreshold == 0 {
		c.Ladder.YellowHoldsThreshold = 3
	}
	if c.Ladder.YellowWindow == 0 {
		c.Ladder.YellowWindow = 10 * time.Minute
	}
	if c.Delegation.SigningKeySecret == "" {
		c.Delegation.SigningKeySecret = "delegation/signing_key"
	}
	if c.Delegation.TokenTTL == 0 {
		c.Delegation.TokenTTL = 15 * time.Minute
	}
	if c.Delegation.MaxDepth == 0 {
		c.Delegation.MaxDepth = 5
	}
	if c.Delegation.BypassOriginLevel == "" {
		c.Delegation.BypassOriginLevel = "SUPERVISED"
	}
	if c.Population.HeartbeatInterval == 0 {
		c.Population.HeartbeatInterval = 15 * time.Second
	}
	if c.Population.StaleAfter == 0 {
		c.Population.StaleAfter = 45 * time.Second
	}
	if c.Population.SpikeCooldown == 0 {
		c.Population.SpikeCooldown = 5 * time.Minute
	}
	if c.Counters.Provider == "" {
		c.Counters.Provider = "memory"
	}
	if c.Approvals.GrantTTL == 0 {
		c.Approvals.GrantTTL = 15 * time.Minute
	}
	if c.Overrides.SweepInterval == 0 {
		c.Overrides.SweepInterval = 5 * time.Second
	}
	if c.Memory.PromotionDelay == 0 {
		c.Memory.PromotionDelay = 10 * time.Minute
	}
	if c.Memory.PromotionPoll == 0 {
		c.Memory.PromotionPoll = 30 * time.Second
	}
	if c.Memory.SnapshotRetention == 0 {
		c.Memory.SnapshotRetention = 30 * 24 * time.Hour
	}
	if c.Retention.SweepInterval == 0 {
		c.Retention.SweepInterval = time.Hour
	}
	if c.Swarm.BreakerN == 0 {
		c.Swarm.BreakerN = 5
	}
	if c.Swarm.BreakerWindow == 0 {
		c.Swarm.BreakerWindow = 10 * time.Minute
	}
	if c.Swarm.FanoutLimit == 0 {
		c.Swarm.FanoutLimit = 10
	}
	if c.Swarm.DepthLimit == 0 {
		c.Swarm.DepthLimit = c.Delegation.MaxDepth
	}
	if c.Swarm.ConvergeN == 0 {
		c.Swarm.ConvergeN = 8
	}
	if c.Swarm.ConvergeWindow == 0 {
		c.Swarm.ConvergeWindow = 10 * time.Minute
	}
	if c.Swarm.SweepInterval == 0 {
		c.Swarm.SweepInterval = 15 * time.Second
	}
	if c.Map.Window == 0 {
		c.Map.Window = 5 * time.Minute
	}
	if c.Map.RollupInterval == 0 {
		c.Map.RollupInterval = 10 * time.Second
	}
	if c.Map.Retention == 0 {
		c.Map.Retention = 30 * 24 * time.Hour
	}
	if c.Map.EncodedParamMin == 0 {
		c.Map.EncodedParamMin = 256
	}
	if c.Baseline.Days == 0 {
		c.Baseline.Days = 14
	}
	if c.Baseline.Sigma == 0 {
		c.Baseline.Sigma = 3
	}
	if c.Baseline.MedianFactor == 0 {
		c.Baseline.MedianFactor = 5
	}
	if c.Baseline.MinHistoryDays == 0 {
		c.Baseline.MinHistoryDays = 3
	}
	if c.Baseline.MinCount == 0 {
		c.Baseline.MinCount = 20
	}
	if c.AgentGW.Listen == "" {
		c.AgentGW.Listen = "127.0.0.1:9091"
	}
	if c.Secrets.VaultMount == "" {
		c.Secrets.VaultMount = "secret"
	}
	if c.Secrets.VaultPrefix == "" {
		c.Secrets.VaultPrefix = "fortik/"
	}
}

// Validate rejects configurations that would weaken enforcement.
func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("config: database_url (or FORTIK_DATABASE_URL) is required")
	}
	if (c.Secrets.Provider == "file" || c.Secrets.Provider == "encfile") && c.Secrets.Dir == "" {
		return fmt.Errorf("config: secrets.dir is required for the %s secret provider", c.Secrets.Provider)
	}
	if c.Secrets.Provider == "vault" && c.Secrets.VaultAddr == "" {
		return fmt.Errorf("config: secrets.vault_addr is required for the vault secret provider")
	}
	if c.Auth.DevLogin.Enabled && !isLoopback(c.API.Listen) {
		return fmt.Errorf("config: auth.dev_login is only allowed when api.listen is a loopback address (got %q)", c.API.Listen)
	}
	switch c.Counters.Provider {
	case "memory", "redis":
	default:
		return fmt.Errorf("config: counters.provider must be memory|redis")
	}
	if c.Counters.Provider == "redis" && c.Counters.RedisURL == "" {
		return fmt.Errorf("config: counters.redis_url is required for the redis provider")
	}
	switch c.Events.Provider {
	case "memory", "nats":
	default:
		return fmt.Errorf("config: events.provider must be memory|nats")
	}
	for k, u := range c.PGProxy.Upstreams {
		switch u.Environment {
		case "prod", "staging", "dev":
		default:
			return fmt.Errorf("config: pgproxy.upstreams.%s.environment must be prod|staging|dev (got %q)", k, u.Environment)
		}
		if u.Host == "" || u.User == "" {
			return fmt.Errorf("config: pgproxy.upstreams.%s needs host and user", k)
		}
	}
	for _, e := range c.Fail.GreenReadAllowlist {
		if e.System == "" || e.Agent == "" {
			return fmt.Errorf("config: fail.green_read_allowlist entries need system and agent")
		}
	}
	return nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
