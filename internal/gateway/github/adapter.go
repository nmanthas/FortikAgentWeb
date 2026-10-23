// Package github is the gateway adapter for the GitHub REST API, mounted at
// /gw/github/. Agents call it with their Fortik agent token exactly as they
// would call api.github.com; each request is mapped to a Fortik Action
// (repo, branch, operation, protected, paths), enriched with branch
// protection / default branch / PR base, decided by decide.Service, and only
// then forwarded with a GitHub App installation token that is narrowed to
// the one repository and the permissions the operation needs (∩ the agent's
// access profile). The token never reaches the agent: it is not returned,
// and any echo of it in an upstream response is redacted.
//
// Reduced forms: record_ref (the previous ref sha, or the PR state for
// close_pr, is captured into an undo handle BEFORE forwarding). Any other
// reduced-form key makes Forward refuse (gateway.ErrReducedFormUnsupported).
package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"fortik/internal/broker"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/undo"
)

// Undo handle kinds this adapter prepares and UndoExecutor reverses.
const (
	KindRef = "github_ref" // {repo, ref, previous_sha}: force-update (or recreate/delete) the ref
	KindPR  = "github_pr"  // {repo, pr, previous_state}: reopen a closed PR
)

// Rule ids of refusals made by Forward itself (returned as
// *gateway.RefusedError, which the gateway server answers with 403
// fortik_refused). They back up policy: the access gate (POL-024) normally
// denies these requests before Forward runs.
const (
	RuleProfile = "GW-GITHUB-PROFILE" // repository or permission outside the access profile
	RuleScope   = "GW-GITHUB-SCOPE"   // not a repository-scoped request, or repo outside the installation account
	RuleUnknown = "GW-GITHUB-UNKNOWN" // unclassified request (policy denies it first: POL-002)
	RuleRefused = "GW-GITHUB"         // identity/decision mismatch or state changed since the decision
)

// ErrResponseTooLarge: the upstream answer exceeded MaxResponseBytes (502).
var ErrResponseTooLarge = errors.New("github: upstream response exceeds the gateway limit")

func refuse(rule, format string, args ...any) error {
	return &gateway.RefusedError{RuleID: rule, Reason: fmt.Sprintf(format, args...)}
}

// IssuanceRecorder stores gateway-minted credentials in credential_issuances
// and the Diary (broker.Broker.RecordIssuance satisfies it). Credentials
// passed to it never contain the secret.
type IssuanceRecorder interface {
	RecordIssuance(ctx context.Context, c broker.Credential, agentID, instanceID string) error
}

// Config wires the adapter. Source, Profiles, Undo and Recorder are required.
type Config struct {
	Source   integrations.Source    // the "github" integration
	Profiles ghbroker.ProfileSource // access profiles (access.Store)
	Undo     undo.Store             // undo handles for record_ref
	Recorder IssuanceRecorder       // credential_issuances + Diary for minted tokens
	Client   *ghbroker.Client       // shared with the broker adapter; nil = new client
	// UndoRetention is how long a github_ref/github_pr handle stays undoable
	// (default 7 days: GitHub may garbage-collect unreachable commits later).
	UndoRetention time.Duration
	// MaxResponseBytes bounds a buffered upstream response (default 32 MiB).
	MaxResponseBytes int64
	Log              *slog.Logger
	Now              func() time.Time
}

// Adapter implements gateway.Adapter for prefix "github".
type Adapter struct {
	cfg    Config
	client *ghbroker.Client
	log    *slog.Logger

	tokens *tokenCache
	flight singleflight.Group

	lookupMu   sync.Mutex
	protection map[string]cachedBool   // fp|repo|branch -> protected
	defaults   map[string]cachedString // fp|repo -> default branch
}

type cachedBool struct {
	v  bool
	at time.Time
}

type cachedString struct {
	v  string
	at time.Time
}

// lookupTTL is how long branch protection and default branch lookups are cached.
const lookupTTL = 60 * time.Second

var _ gateway.Adapter = (*Adapter)(nil)

// New builds the adapter.
func New(cfg Config) (*Adapter, error) {
	if cfg.Source == nil || cfg.Profiles == nil || cfg.Undo == nil || cfg.Recorder == nil {
		return nil, errors.New("github gateway adapter: Source, Profiles, Undo and Recorder are required")
	}
	if cfg.Client == nil {
		cfg.Client = ghbroker.NewClient(nil)
	}
	if cfg.UndoRetention <= 0 {
		cfg.UndoRetention = 7 * 24 * time.Hour
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 32 << 20
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Adapter{
		cfg: cfg, client: cfg.Client, log: cfg.Log,
		tokens:     newTokenCache(),
		protection: map[string]cachedBool{},
		defaults:   map[string]cachedString{},
	}, nil
}

// Prefix is the gateway mount: /gw/github/.
func (a *Adapter) Prefix() string { return "github" }

// UndoExecutor returns the executor for KindRef/KindPR sharing this
// adapter's client and integration source.
func (a *Adapter) UndoExecutor() *UndoExecutor { return NewUndoExecutor(a.client, a.cfg.Source, a.log) }

// settings resolves the integration; a missing one is ghbroker.ErrNotConfigured.
func (a *Adapter) settings(ctx context.Context) (ghbroker.Settings, error) {
	res, err := a.cfg.Source.Get(ctx, ghbroker.IntegrationKey)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return ghbroker.Settings{}, fmt.Errorf("%w", ghbroker.ErrNotConfigured)
	}
	if err != nil {
		return ghbroker.Settings{}, fmt.Errorf("github: load integration: %w", err)
	}
	return a.client.Settings(res)
}
