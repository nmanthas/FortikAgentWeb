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
}

// Schema describes one integration type for the UI.
type Schema struct {
	System string  `json:"system"` // google_workspace | github | aws | postgres
	Title  string  `json:"title"`
	Multi  bool    `json:"multi"` // postgres: many instances keyed postgres:<name>
	Fields []Field `json:"fields"`
}

// Integration is one configured instance (never contains secret values).
type Integration struct {
	Key          string          `json:"key"` // "github" or "postgres:acme_prod"
	System       string          `json:"system"`
	Config       json.RawMessage `json:"config"`
	SecretFields []string        `json:"secret_fields"` // names set, never values
	Status       string          `json:"status"`        // unconfigured | configured | ok | error
	LastTestedAt *time.Time      `json:"last_tested_at,omitempty"`
	LastError    string          `json:"last_error,omitempty"`
	UpdatedBy    string          `json:"updated_by"`
	UpdatedAt    time.Time       `json:"updated_at"`
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
