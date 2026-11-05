package netsuite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

// Prefix is the gateway path prefix: agents call /gw/netsuite/services/rest/...
const Prefix = "netsuite"

// KindRecord is the undo kind for a snapshotted record update.
const KindRecord = "netsuite_record"

// Reduced-form keys this adapter honours.
const ReducedSnapshot = "record_snapshot"

// Refusal rule ids of the adapter itself (after policy allowed).
const (
	RuleRefused  = "GW-NETSUITE"
	RuleSnapshot = "GW-NETSUITE-SNAPSHOT"
)

// RecordUndoData is handle_json for KindRecord. The previous field values are
// NOT here: they are customer data, kept encrypted in Fortik's secret store
// under Secret (a pointer), and deleted after the undo or at expiry.
type RecordUndoData struct {
	Key        string   `json:"key,omitempty"` // the connection (tenant); empty in handles before multi-tenancy
	RecordType string   `json:"record_type"`
	RecordID   string   `json:"record_id"`
	Fields     []string `json:"fields"`
	Secret     string   `json:"secret"`
	Account    string   `json:"account"`
}

// Adapter is the gateway adapter for NetSuite.
type Adapter struct {
	src       integrations.Source
	client    *Client
	undo      undo.Store
	store     secrets.Store
	retention time.Duration
	log       *slog.Logger
}

var _ gateway.Adapter = (*Adapter)(nil)

// NewAdapter wires the adapter. store keeps the encrypted update snapshots.
func NewAdapter(src integrations.Source, client *Client, us undo.Store, store secrets.Store, retention time.Duration, log *slog.Logger) (*Adapter, error) {
	if src == nil || us == nil || store == nil {
		return nil, errors.New("netsuite: integration source, undo store and secret store are required")
	}
	if client == nil {
		client = NewClient(nil)
	}
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Adapter{src: src, client: client, undo: us, store: store, retention: retention, log: log}, nil
}

func (a *Adapter) Prefix() string { return Prefix }

// Client is shared with the connector (token cache, Drop on kill).
func (a *Adapter) Client() *Client { return a.client }

// HeaderIntegration selects the NetSuite tenant (logical integration id,
// e.g. netsuite:acme) when more than one NetSuite REST connection exists.
const HeaderIntegration = "X-Fortik-Integration"

func (a *Adapter) Map(ctx context.Context, _ authz.Principal, r *http.Request, body []byte) (gateway.Op, error) {
	path := strings.TrimPrefix(r.URL.Path, "/gw/"+Prefix)
	m := MapRequest(r.Method, path, r.URL.RawQuery, body)
	op := gateway.Op{Body: body}
	op.Action.System = System
	conn, reason := a.resolve(ctx, r.Header.Get(HeaderIntegration))
	if reason != "" {
		// Never forwarded to a guessed tenant: decided as UNKNOWN, recorded, refused.
		op.Action.Verb = "UNKNOWN"
		op.Action.Target = map[string]any{"transport": integrations.TransportREST, "operation": "unknown", "path": clip(path, 300), "reason": reason}
		op.State = m
		return op, nil
	}
	m.Key, m.IntegrationID = conn.key, conn.integrationID
	op.State = m
	op.Action.Verb = m.Verb
	t := m.Target()
	t["transport"] = integrations.TransportREST
	t["integration_id"] = conn.integrationID
	t["connection"] = conn.key
	if conn.account != "" {
		t["tenant"] = conn.account
	}
	op.Action.Target = t
	return op, nil
}

type restConn struct{ key, integrationID, account string }

// resolve picks the NetSuite REST connection for a request: the one the
// X-Fortik-Integration header names, or the only one configured. With none
// configured the legacy key is used (the gateway answers 503 after the
// decision). A non-empty reason refuses the request.
func (a *Adapter) resolve(ctx context.Context, want string) (restConn, string) {
	want = strings.TrimSpace(want)
	list, err := a.src.List(ctx, System)
	if err != nil {
		return restConn{}, "could not read the NetSuite connections"
	}
	if want != "" {
		for _, r := range list {
			if r.IntegrationID == want {
				return restConn{key: r.Key, integrationID: r.IntegrationID, account: r.Text("account_id")}, ""
			}
		}
		return restConn{}, "no NetSuite REST connection for integration " + clip(want, 80)
	}
	switch len(list) {
	case 0:
		_, id, _ := integrations.LogicalID(IntegrationKey)
		return restConn{key: IntegrationKey, integrationID: id}, ""
	case 1:
		return restConn{key: list[0].Key, integrationID: list[0].IntegrationID, account: list[0].Text("account_id")}, ""
	}
	return restConn{}, fmt.Sprintf("%d NetSuite tenants are connected: name one with the %s header (e.g. %s)", len(list), HeaderIntegration, list[0].IntegrationID)
}

func (a *Adapter) Enrich(context.Context, authz.Principal, *gateway.Op) error { return nil }

func (a *Adapter) settings(ctx context.Context, key string) (Settings, error) {
	if key == "" {
		key = IntegrationKey
	}
	r, err := a.src.Get(ctx, key)
	if err != nil {
		if errors.Is(err, integrations.ErrNotConfigured) {
			return Settings{}, &gateway.NotConfiguredError{System: key}
		}
		return Settings{}, err
	}
	s, err := SettingsFrom(r)
	if err != nil {
		if errors.Is(err, integrations.ErrSecretMissing) {
			return Settings{}, &gateway.NotConfiguredError{System: key}
		}
		return Settings{}, err
	}
	return s, nil
}

// Forward runs an allowed request with Fortik's token. A record_snapshot
// reduced form snapshots the fields an update changes BEFORE forwarding;
// if that is impossible the update is refused, never run without it.
func (a *Adapter) Forward(ctx context.Context, p authz.Principal, op *gateway.Op, out decide.Outcome, w http.ResponseWriter, r *http.Request) error {
	m, ok := op.State.(Request)
	if !ok || out.Action.AgentID != p.Name {
		return &gateway.RefusedError{RuleID: RuleRefused, Reason: "request state or identity does not match the decision"}
	}
	snapshot := false
	for k, v := range out.Result.ReducedForm {
		switch k {
		case ReducedSnapshot:
			snapshot = v == true
		default:
			return gateway.ErrReducedFormUnsupported{Key: k}
		}
	}
	s, err := a.settings(ctx, m.Key)
	if err != nil {
		return err
	}
	actionID := out.Action.ActionID
	if snapshot {
		if m.Operation != OpUpdate || m.RecordID == "" {
			return &gateway.RefusedError{RuleID: RuleSnapshot, Reason: "a snapshot is required but only single-record updates can be snapshotted: refused"}
		}
		if err := a.snapshot(ctx, s, m, p, actionID, out.Action.AgentID); err != nil {
			a.log.Warn("netsuite: snapshot failed; update refused", "action_id", actionID, "err", err)
			return &gateway.RefusedError{RuleID: RuleSnapshot, Reason: "could not snapshot the record before the update: refused (" + clip(err.Error(), 160) + ")"}
		}
	}
	hdr := http.Header{}
	for _, h := range []string{"Content-Type", "Accept", "Prefer"} {
		if v := r.Header.Get(h); v != "" {
			hdr.Set(h, v)
		}
	}
	var body []byte
	if len(op.Body) > 0 {
		body = op.Body
	}
	res, b, err := a.client.Do(ctx, s, r.Method, m.Path, m.RawQuery, body, hdr)
	if snapshot {
		sctx := context.WithoutCancel(ctx)
		if err == nil && res.StatusCode >= 200 && res.StatusCode < 300 {
			if aerr := a.undo.Activate(sctx, actionID); aerr != nil {
				a.log.Error("netsuite: activate undo handle", "action_id", actionID, "err", aerr)
			}
		} else {
			note := "the update did not complete"
			if res != nil {
				note = fmt.Sprintf("the update returned HTTP %d", res.StatusCode)
			}
			_ = a.undo.Fail(sctx, actionID, note)
			_ = a.store.Delete(sctx, snapshotSecret(actionID))
		}
	}
	if err != nil {
		return fmt.Errorf("netsuite forward: %w", err)
	}
	for _, h := range []string{"Content-Type", "Location"} {
		if v := res.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write([]byte(redact(string(b))))
	return nil
}

func snapshotSecret(actionID string) string { return "netsuite_undo_" + strings.ToLower(actionID) }

// snapshot reads the record and keeps the previous value of every field the
// update sets (absent fields as null), encrypted, then prepares the handle.
func (a *Adapter) snapshot(ctx context.Context, s Settings, m Request, p authz.Principal, actionID, agentID string) error {
	res, b, err := a.client.Do(ctx, s, http.MethodGet, recordPrefix+m.RecordType+"/"+m.RecordID, "", nil, nil)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("read before update: HTTP %d: %s", res.StatusCode, clip(nsError(b), 120))
	}
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(b, &rec); err != nil {
		return errors.New("read before update: malformed record")
	}
	lower := map[string]json.RawMessage{}
	for k, v := range rec {
		lower[strings.ToLower(k)] = v
	}
	prev := map[string]json.RawMessage{}
	for _, f := range m.Fields {
		if v, ok := lower[f]; ok {
			prev[f] = v
		} else {
			prev[f] = json.RawMessage("null")
		}
	}
	blob, _ := json.Marshal(prev)
	name := snapshotSecret(actionID)
	if err := a.store.Put(ctx, name, blob); err != nil {
		return fmt.Errorf("store snapshot: %w", err)
	}
	data, _ := json.Marshal(RecordUndoData{Key: s.Key, RecordType: m.RecordType, RecordID: m.RecordID, Fields: m.Fields, Secret: name, Account: s.AccountID})
	h := undo.Handle{ActionID: actionID, AgentID: agentID, Kind: KindRecord, Data: data, ExpiresAt: time.Now().Add(a.retention)}
	if err := a.undo.Prepare(ctx, h, p.Actor()); err != nil {
		_ = a.store.Delete(context.WithoutCancel(ctx), name)
		return fmt.Errorf("prepare undo: %w", err)
	}
	return nil
}

// UndoExecutor restores snapshotted fields (POST /v1/undo/{id}).
type UndoExecutor struct {
	src    integrations.Source
	client *Client
	store  secrets.Store
}

var _ undo.Executor = (*UndoExecutor)(nil)

// UndoExecutor returns the executor sharing the adapter's client and store.
func (a *Adapter) UndoExecutor() *UndoExecutor {
	return &UndoExecutor{src: a.src, client: a.client, store: a.store}
}

func (e *UndoExecutor) Kinds() []string { return []string{KindRecord} }

// Undo PATCHes the snapshotted previous values back. NetSuite's REST API has
// no conditional update, so this is last-writer-wins on exactly those fields:
// a change someone made to them after the update is overwritten (the result
// says so). Idempotent: restoring the same values twice is harmless.
func (e *UndoExecutor) Undo(ctx context.Context, h undo.Handle) (map[string]any, error) {
	var d RecordUndoData
	if err := json.Unmarshal(h.Data, &d); err != nil || d.RecordType == "" || d.RecordID == "" || d.Secret == "" {
		return nil, errors.New("netsuite undo: incomplete handle")
	}
	key := d.Key
	if key == "" {
		key = IntegrationKey
	}
	r, err := e.src.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("netsuite undo: %w", err)
	}
	s, err := SettingsFrom(r)
	if err != nil {
		return nil, fmt.Errorf("netsuite undo: %w", err)
	}
	if !strings.EqualFold(s.AccountID, d.Account) {
		return nil, fmt.Errorf("netsuite undo: the integration now points at account %s, the snapshot is from %s: refused", s.AccountID, d.Account)
	}
	blob, err := e.store.Get(ctx, d.Secret)
	if err != nil {
		return nil, fmt.Errorf("netsuite undo: snapshot unavailable: %w", err)
	}
	res, b, err := e.client.Do(ctx, s, http.MethodPatch, recordPrefix+d.RecordType+"/"+d.RecordID, "", blob, nil)
	if err != nil {
		return nil, fmt.Errorf("netsuite undo: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("netsuite undo: HTTP %d: %s", res.StatusCode, clip(nsError(b), 200))
	}
	_ = e.store.Delete(ctx, d.Secret)
	return map[string]any{"record_type": d.RecordType, "record_id": d.RecordID, "fields_restored": d.Fields,
		"note": "previous values PATCHed back (last writer wins: changes made to these fields after the update are overwritten)"}, nil
}
