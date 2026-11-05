// Package integrations stores connection settings for the systems Fortik
// brokers. Non-secret config lives in Postgres; secret fields go only to the
// secret store (secrets.Store) and are write-only through the API.
package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Field types rendered by the console.
const (
	FieldText     = "text"
	FieldTextarea = "textarea"
	FieldPassword = "password"
	FieldList     = "list"
	FieldSelect   = "select"
	FieldNumber   = "number"
	FieldBool     = "bool"
)

type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Secret   bool     `json:"secret"`
	Required bool     `json:"required"`
	Help     string   `json:"help,omitempty"`
	Options  []string `json:"options,omitempty"`
	Default  any      `json:"default,omitempty"`
	// Managed secrets are written by Fortik itself (e.g. OAuth tokens it
	// obtained); they cannot be set through the API, are not shown in
	// forms, and are deleted with the integration.
	Managed bool `json:"managed,omitempty"`
	// ShowWhen: the field applies only when another field of the same form
	// has one of these values (e.g. client_secret only for one auth type).
	// Forms hide it otherwise; stored values are kept.
	ShowWhen map[string][]string `json:"show_when,omitempty"`
}

// Transports a connection can use.
const (
	TransportREST   = "rest_api" // the provider's HTTP API, through Fortik's gateway or broker
	TransportMCP    = "mcp"      // the provider's MCP server, through Fortik's MCP endpoint
	TransportNative = "native"   // another wire protocol (Postgres, Temporal gRPC, Redis)
)

// Schema describes one connection type (one transport of one provider) for
// the UI. Several connection types of one provider can belong to one
// logical application integration (a tenant), at most one per transport.
type Schema struct {
	System string `json:"system"` // the connection type, e.g. netsuite (REST), netsuite_quickstart (MCP)
	Title  string `json:"title"`
	Multi  bool   `json:"multi"` // postgres: many instances keyed postgres:<name>
	// OptionalInstance: both the single legacy key (netsuite) and
	// instance keys (netsuite:<tenant>) are accepted.
	OptionalInstance bool    `json:"optional_instance,omitempty"`
	Provider         string  `json:"provider"`              // the application, e.g. netsuite
	Transport        string  `json:"transport"`             // rest_api | mcp | native
	Environment      string  `json:"environment,omitempty"` // provider-specific (netsuite: full | quickstart)
	Fields           []Field `json:"fields"`
}

// Integration is one configured instance (never contains secret values).
type Integration struct {
	Key    string `json:"key"` // "github" or "postgres:acme_prod"
	System string `json:"system"`
	// IntegrationID is the logical application integration (provider
	// tenant) this connection belongs to, e.g. netsuite:acme; Transport is
	// how this connection reaches it.
	IntegrationID string          `json:"integration_id"`
	Transport     string          `json:"transport"`
	Config        json.RawMessage `json:"config"`
	SecretFields  []string        `json:"secret_fields"` // names set, never values
	Status        string          `json:"status"`        // unconfigured | configured | ok | error
	LastTestedAt  *time.Time      `json:"last_tested_at,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	UpdatedBy     string          `json:"updated_by"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// Resolved is config + secrets for in-process use by adapters only.
type Resolved struct {
	Integration
	ConfigMap map[string]any
	Secrets   map[string]string
}

var (
	ErrNotConfigured = errors.New("integration not configured")
	ErrInvalid       = errors.New("invalid integration settings")
	// ErrSecretMissing: the integration is configured (its row exists and is
	// not "unconfigured") but a required secret cannot be found: it was
	// lost from the secret store or deleted out of band. It wraps
	// ErrNotConfigured, so callers that only need "usable or not" keep
	// working; callers that would otherwise report "nothing to do" for an
	// unconfigured system (queue containment) must check it first and fail.
	ErrSecretMissing = fmt.Errorf("%w: a required secret is missing", ErrNotConfigured)
)

// Tester performs a live connection test for one system.
type Tester interface {
	System() string
	Test(ctx context.Context, r Resolved) error
}

// Source is what adapters use to obtain current settings (cached briefly;
// changes made in the UI take effect within seconds without restart).
type Source interface {
	Get(ctx context.Context, key string) (Resolved, error) // ErrNotConfigured if absent
	List(ctx context.Context, system string) ([]Resolved, error)
}
