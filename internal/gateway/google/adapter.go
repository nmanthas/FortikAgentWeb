// Package google is the gateway adapter for Gmail and Drive (prefix
// "google"). Agents call /gw/google/gmail/v1/..., /gw/google/drive/v3/...
// and the /upload/ variants with their Fortik agent token. Each request is
// mapped to an Action (recipients, shares, deletions...), decided, and only
// then executed with a domain-wide-delegation token that impersonates the
// agent's workspace_user. The Google token never leaves the gateway.
//
// Reduced forms honoured: delay_send_seconds (Gmail delayed queue),
// narrow_share and record_permission (Drive). Any other key is refused.
package google

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/secrets"
)

// Default upstream bases (overridable in config.GatewayConfig for tests).
// Paths are appended as Google documents them: /gmail/v1/..., /upload/gmail/v1/...,
// /drive/v3/..., /upload/drive/v3/....
const (
	DefaultGmailBaseURL   = "https://gmail.googleapis.com"
	DefaultDriveBaseURL   = "https://www.googleapis.com"
	DefaultDriveUploadURL = "https://www.googleapis.com"
)

// Undo handle kinds this package prepares and reverses.
const (
	KindGmailDelayedSend = "gmail_delayed_send"
	KindDrivePermission  = "drive_permission"
)

// Diary event types written by this package.
const (
	EventDelayedQueued    = "gmail.delayed_send.queued"
	EventDelayedSent      = "gmail.delayed_send.sent"
	EventDelayedCancelled = "gmail.delayed_send.cancelled"
	EventDelayedFailed    = "gmail.delayed_send.failed"
	EventDelayedRetry     = "gmail.delayed_send.retrying"
	// EventDelayedLate records the real outcome of a send whose row had
	// already been finalised (e.g. swept as outcome-unknown) while it was
	// still in flight. The row's final state is not rewritten.
	EventDelayedLate = "gmail.delayed_send.late_outcome"
)

// LabelFunc supplies data labels for a mapped request before Decide. Label
// propagation arrives in Phase 5; until then this is a hook (tests use it).
type LabelFunc func(ctx context.Context, agentID string, op *gateway.Op) ([]string, error)

// Options configures the adapter.
type Options struct {
	Config    config.GatewayConfig
	Source    integrations.Source // google_workspace settings + service account secret
	Directory AgentDirectory      // agents.workspace_user (PGDirectory in production)
	Pool      *pgxpool.Pool       // delayed_sends, undo_handles
	Diary     *diary.Diary
	// Secrets holds gateway/delayed_send_key. It must implement secrets.Store
	// for the key to be created on first use; with a read-only provider the
	// key must already exist or delayed sends are refused.
	Secrets    secrets.Provider
	Issuances  IssuanceRecorder // optional: records each token mint (broker.Broker)
	HTTPClient *http.Client     // upstream + token endpoint (default: 30s timeout)
	Log        *slog.Logger
	Now        func() time.Time
	// PermissionUndoTTL is how long a recorded Drive permission stays undoable (default 7 days).
	PermissionUndoTTL time.Duration
	// DelayedUndoGrace keeps a delayed-send handle undoable this long after
	// send_at in case the worker is late (default 24h).
	DelayedUndoGrace time.Duration
	Labels           LabelFunc
}

// Adapter implements gateway.Adapter for Google Workspace.
type Adapter struct {
	cfg       config.GatewayConfig
	src       integrations.Source
	dir       AgentDirectory
	pool      *pgxpool.Pool
	diary     *diary.Diary
	keys      *dataKey
	client    *http.Client
	tokens    *tokenMinter
	log       *slog.Logger
	now       func() time.Time
	permTTL   time.Duration
	undoGrace time.Duration
	labels    LabelFunc

	gmailBase, driveBase, driveUpload string
}

var _ gateway.Adapter = (*Adapter)(nil)

// New builds the adapter.
func New(o Options) (*Adapter, error) {
	if o.Directory == nil || o.Pool == nil || o.Diary == nil || o.Secrets == nil {
		return nil, errors.New("google adapter: Directory, Pool, Diary and Secrets are required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.PermissionUndoTTL <= 0 {
		o.PermissionUndoTTL = 7 * 24 * time.Hour
	}
	if o.DelayedUndoGrace <= 0 {
		o.DelayedUndoGrace = 24 * time.Hour
	}
	a := &Adapter{
		cfg: o.Config, src: o.Source, dir: o.Directory, pool: o.Pool, diary: o.Diary,
		keys:   &dataKey{sec: o.Secrets, name: DelayedSendKeySecret},
		client: o.HTTPClient, log: o.Log.With("adapter", "google"), now: o.Now,
		permTTL: o.PermissionUndoTTL, undoGrace: o.DelayedUndoGrace, labels: o.Labels,
		gmailBase:   base(o.Config.GmailBaseURL, DefaultGmailBaseURL),
		driveBase:   base(o.Config.DriveBaseURL, DefaultDriveBaseURL),
		driveUpload: base(o.Config.DriveUploadURL, DefaultDriveUploadURL),
	}
	a.tokens = newTokenMinter(o.HTTPClient, o.Config.GoogleTokenURL, o.Issuances, o.Now)
	return a, nil
}

func base(v, def string) string {
	if v == "" {
		v = def
	}
	return strings.TrimRight(v, "/")
}

// Prefix is the gateway path prefix: /gw/google/.
func (a *Adapter) Prefix() string { return "google" }

// subject returns the agent's workspace user ("" when none is set).
func (a *Adapter) subject(ctx context.Context, agentID string) (string, error) {
	return a.dir.WorkspaceUser(ctx, agentID)
}

// RevokeAgent drops every Google token the gateway holds for the agent. The
// tokens never left the gateway, so this plus the agent's new level (which
// makes Decide refuse) is a complete revocation.
func (a *Adapter) RevokeAgent(_ context.Context, agentID string) (string, error) {
	n := a.tokens.dropAgent(agentID, "")
	return "google: gateway-held tokens dropped (" + strconv.Itoa(n) + "); tokens were never released to the agent", nil
}

// Enrich completes the classification with lookups that need the
// integration: internal domains, the stored draft for drafts.send, the
// existing grantee for permissions.update, and data labels.
func (a *Adapter) Enrich(ctx context.Context, p authz.Principal, op *gateway.Op) error {
	st, ok := op.State.(*opState)
	if !ok || st == nil || st.unknown {
		return nil
	}
	s, serr := a.settings(ctx)
	var nc *gateway.NotConfiguredError
	configured := serr == nil
	if serr != nil && !errors.As(serr, &nc) {
		return serr
	}
	switch {
	case st.send != nil:
		if st.send.msg == nil && configured {
			if err := a.fetchDraft(ctx, p, op, st, s); err != nil {
				return err
			}
		}
		a.classifySend(op, st, s, configured)
	case st.share != nil:
		if !st.share.create && configured {
			if err := a.fetchGrantee(ctx, p, op, st, s); err != nil {
				return err
			}
		}
		a.classifyShare(op, st, s, configured)
	}
	if a.labels != nil {
		labels, err := a.labels(ctx, p.Name, op)
		if err != nil {
			return err
		}
		op.Action.PayloadSummary.DataLabels = append(op.Action.PayloadSummary.DataLabels, labels...)
	}
	return nil
}
