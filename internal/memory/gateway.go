package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/gateway"
	"fortik/internal/httpx"
	"fortik/internal/undo"
)

// GatewayPrefix is the agent gateway prefix: /gw/memory/...
const GatewayPrefix = "memory"

// ReducedStaging is the reduced-form key of POL-903.
const ReducedStaging = "memory_staging"

// Refusal rule ids of the memory gateway (the action was allowed by policy
// but could not be carried out as asked).
const (
	RuleInvalid  = "MEM-INVALID"   // the store rejected the request (e.g. embedding size)
	RuleNoUndo   = "MEM-NO-UNDO"   // the undo handle could not be prepared: the write is refused
	RuleNotFound = "MEM-NOT-FOUND" // no such item
)

// MaxGatewayBody bounds a memory request body (content + embedding + metadata).
const MaxGatewayBody = 2 << 20

// GatewayAdapter is the agent gateway adapter for memory (gateway.Adapter,
// prefix "memory"; pass it to gateway.NewServer). The gateway authenticates
// the agent, Map builds the Action and Decide runs before Forward touches the
// customer's store:
//
//	POST   /gw/memory/{store}/{namespace}/items       REMEMBER (always staged, undoable until promoted)
//	POST   /gw/memory/{store}/{namespace}/query       READ (promoted items plus the caller's own staged ones)
//	DELETE /gw/memory/{store}/{namespace}/items/{id}  DELETE (not undoable; held by policy)
//
// Any other path or method maps to verb UNKNOWN, which policy denies.
type GatewayAdapter struct {
	svc           *Service
	undo          undo.Store
	undoRetention time.Duration
	log           *slog.Logger
}

var _ gateway.Adapter = (*GatewayAdapter)(nil)

// NewGatewayAdapter builds the adapter. undoStore records the memory_staging
// handle of every write before the write runs (required: a write whose undo
// cannot be prepared is refused). undoRetention bounds how long a handle of
// an item that stays staged remains usable (config.UndoConfig.SnapshotRetention,
// 30 days); promotion closes it earlier.
func NewGatewayAdapter(svc *Service, undoStore undo.Store, undoRetention time.Duration, log *slog.Logger) (*GatewayAdapter, error) {
	if svc == nil || undoStore == nil {
		return nil, errors.New("memory gateway: service and undo store are required")
	}
	if undoRetention <= 0 {
		undoRetention = 30 * 24 * time.Hour
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &GatewayAdapter{svc: svc, undo: undoStore, undoRetention: undoRetention, log: log}, nil
}

func (g *GatewayAdapter) Prefix() string { return GatewayPrefix }

// WriteRequest is the body of POST .../items.
type WriteRequest struct {
	ID        string    `json:"id,omitempty"` // optional; generated when empty
	Content   string    `json:"content"`
	Embedding []float32 `json:"embedding,omitempty"`
	Metadata  Metadata  `json:"metadata,omitempty"` // metadata["labels"]: data labels
}

// Metadata is item metadata: string values only, except "labels", which may
// be a comma-separated string or a JSON array of strings (stored
// comma-separated).
type Metadata map[string]string

func (m *Metadata) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return errors.New("metadata must be an object of strings")
	}
	out := make(Metadata, len(raw))
	for k, v := range raw {
		var str string
		if err := json.Unmarshal(v, &str); err == nil {
			out[k] = str
			continue
		}
		var list []string
		if k == "labels" && json.Unmarshal(v, &list) == nil {
			out[k] = strings.Join(list, ",")
			continue
		}
		return fmt.Errorf("metadata %q must be a string (labels: a string or an array of strings)", k)
	}
	*m = out
	return nil
}

// QueryRequest is the body of POST .../query.
type QueryRequest struct {
	Embedding []float32 `json:"embedding,omitempty"`
	Text      string    `json:"text,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	// IncludeOwnStaged returns the caller's own staged (not yet promoted)
	// writes too (default true). Other agents' staged items are never returned.
	IncludeOwnStaged  *bool `json:"include_own_staged,omitempty"`
	IncludeEmbeddings bool  `json:"include_embeddings,omitempty"`
}

type gwOp struct {
	kind      string // write | query | delete
	store     string
	namespace string
	itemID    string
	write     WriteRequest
	query     QueryRequest
}

// Map turns the request into a memory Action. A malformed request is an
// error (the gateway then decides it as UNKNOWN and refuses it).
func (g *GatewayAdapter) Map(_ context.Context, p authz.Principal, r *http.Request, body []byte) (gateway.Op, error) {
	segs, err := pathSegments(r)
	if err != nil {
		return gateway.Op{}, err
	}
	op := &gwOp{}
	var verb action.Verb
	switch {
	case len(segs) == 3 && segs[2] == "items" && r.Method == http.MethodPost:
		op.kind, verb = "write", action.VerbRemember
	case len(segs) == 3 && segs[2] == "query" && r.Method == http.MethodPost:
		op.kind, verb = "query", action.VerbRead
	case len(segs) == 4 && segs[2] == "items" && r.Method == http.MethodDelete:
		op.kind, verb, op.itemID = "delete", action.VerbDelete, segs[3]
	default:
		return unknown(r), nil
	}
	op.store, op.namespace = segs[0], segs[1]
	if !ValidStoreName(op.store) {
		return gateway.Op{}, fmt.Errorf("store name must match %s", storeName)
	}
	if !ValidNamespace(op.namespace) {
		return gateway.Op{}, fmt.Errorf("namespace must match %s", namespacePattern)
	}
	a := action.Action{System: action.SystemMemory, Verb: verb,
		Target: map[string]any{"store": op.store, "namespace": op.namespace}}
	switch op.kind {
	case "write":
		if err := decodeBody(body, &op.write); err != nil {
			return gateway.Op{}, err
		}
		it := Item{ID: op.write.ID, Namespace: op.namespace, Content: op.write.Content, Embedding: op.write.Embedding,
			Metadata: op.write.Metadata, AgentID: p.Name}
		if err := ValidateItem(it); err != nil {
			return gateway.Op{}, err
		}
		if op.write.ID == "" {
			op.write.ID = action.NewID("mem")
		}
		op.itemID = op.write.ID
		a.Target["item_id"] = op.itemID
		a.PayloadSummary = action.PayloadSummary{Bytes: int64(len(op.write.Content)), DataLabels: Labels(op.write.Metadata)}
		a.Reversible = true // staged: undoable until promoted
	case "query":
		if err := decodeBody(body, &op.query); err != nil {
			return gateway.Op{}, err
		}
		if err := validateEmbedding(op.query.Embedding); err != nil {
			return gateway.Op{}, err
		}
		if op.query.Limit < 0 || op.query.Limit > MaxQueryLimit {
			return gateway.Op{}, fmt.Errorf("limit must be between 1 and %d", MaxQueryLimit)
		}
	case "delete":
		if len(bytes.TrimSpace(body)) > 0 {
			return gateway.Op{}, errors.New("DELETE takes no body")
		}
		if !ValidItemID(op.itemID) {
			return gateway.Op{}, fmt.Errorf("item id must match %s", itemIDPattern)
		}
		a.Target["item_id"] = op.itemID
	}
	return gateway.Op{Action: a, State: op}, nil
}

// pathSegments returns the unescaped segments after /gw/memory/. Segments
// are split before unescaping so an encoded "/" cannot shift them.
func pathSegments(r *http.Request) ([]string, error) {
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/gw/"+GatewayPrefix+"/")
	if !ok {
		return nil, nil
	}
	raw := strings.Split(rest, "/")
	out := make([]string, len(raw))
	for i, s := range raw {
		u, err := url.PathUnescape(s)
		if err != nil {
			return nil, errors.New("malformed path")
		}
		out[i] = u
	}
	return out, nil
}

func unknown(r *http.Request) gateway.Op {
	endpoint := r.Method + " " + r.URL.EscapedPath()
	if len(endpoint) > 512 {
		endpoint = endpoint[:512]
	}
	return gateway.Op{Action: action.Action{System: action.SystemMemory, Verb: "UNKNOWN",
		Target: map[string]any{"endpoint": endpoint, "reason": "unknown memory endpoint"}}}
}

func decodeBody(body []byte, v any) error {
	if len(body) > MaxGatewayBody {
		return fmt.Errorf("request body exceeds %d bytes", MaxGatewayBody)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body: trailing data")
	}
	return nil
}

// Enrich has nothing to look up: the memory context comes from the decide
// enricher (memory access mode).
func (g *GatewayAdapter) Enrich(context.Context, authz.Principal, *gateway.Op) error { return nil }

// Forward executes an allowed action against the customer's store.
func (g *GatewayAdapter) Forward(ctx context.Context, p authz.Principal, gop *gateway.Op, out decide.Outcome, w http.ResponseWriter, _ *http.Request) error {
	op, ok := gop.State.(*gwOp)
	if !ok {
		return errors.New("memory gateway: missing request state")
	}
	for k := range out.Result.ReducedForm {
		if k != ReducedStaging {
			return gateway.ErrReducedFormUnsupported{Key: k}
		}
	}
	st, err := g.svc.stores.Store(ctx, op.store)
	if err != nil {
		return err // not configured -> 503 integration_not_configured
	}
	actionID := out.Action.ActionID
	switch op.kind {
	case "write":
		return g.write(ctx, p, st, op, actionID, w)
	case "query":
		return g.query(ctx, p, st, op, actionID, w)
	case "delete":
		return g.delete(ctx, p, st, op, actionID, w)
	}
	return fmt.Errorf("memory gateway: unknown operation %q", op.kind)
}

// StagingUndo is handle_json of a memory_staging undo handle. The undo drops
// the item only if the write ActionID (the handle's own action) staged it.
type StagingUndo struct {
	Store     string `json:"store"`
	StoreKey  string `json:"store_key"`
	Namespace string `json:"namespace"`
	ItemID    string `json:"item_id"`
	ActionID  string `json:"action_id,omitempty"`
}

// holdNote is the hold reason of a write made while the writer's memory
// access was not full.
func holdNote(mode string) string {
	if mode == "" {
		mode = "unknown (could not be read)"
	}
	return "written while the agent's memory access was " + mode + ": held for review, not promoted at once when access returns to full"
}

func (g *GatewayAdapter) write(ctx context.Context, p authz.Principal, st *PGStore, op *gwOp, actionID string, w http.ResponseWriter) error {
	now := g.svc.now()
	promoteAt := now.Add(g.svc.cfg.PromotionDelay)
	it := Item{ID: op.itemID, Namespace: op.namespace, Content: op.write.Content, Embedding: op.write.Embedding,
		Metadata: op.write.Metadata, AgentID: p.Name, PromoteAt: &promoteAt}

	// A write made while the writer is not at full access (staging_only) is
	// held for review: it is not promoted when access returns to full, it
	// gets a fresh review window first. The mode is read before and after the
	// write; either not full (or unreadable) holds the item.
	if acc, aerr := g.svc.Access(ctx, p.Name); aerr != nil || acc.Mode != AccessFull {
		it.HoldReason = holdNote(acc.Mode)
	}
	// The undo handle is recorded BEFORE the write (Fortik never claims an
	// undo it did not prepare); a write whose handle cannot be prepared is
	// refused.
	raw, err := json.Marshal(StagingUndo{Store: op.store, StoreKey: st.Key(), Namespace: op.namespace, ItemID: op.itemID, ActionID: actionID})
	if err != nil {
		return err
	}
	h := undo.Handle{ActionID: actionID, AgentID: p.Name, Kind: undo.KindMemoryStaging, Data: raw, ExpiresAt: now.Add(g.undoRetention)}
	if err := g.undo.Prepare(ctx, h, p.Actor()); err != nil {
		g.log.Error("memory gateway: undo handle not prepared; write refused", "action_id", actionID, "err", err)
		return &gateway.RefusedError{RuleID: RuleNoUndo, Reason: "the undo handle for this memory write could not be prepared: write refused (nothing was written)"}
	}
	written, werr := st.WriteFor(ctx, it, actionID)
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if werr != nil {
		if ferr := g.undo.Fail(sctx, actionID, "memory write failed: nothing was staged"); ferr != nil {
			g.log.Error("memory gateway: undo handle could not be marked failed", "action_id", actionID, "err", ferr)
		}
		if errors.Is(werr, ErrInvalid) {
			return &gateway.RefusedError{RuleID: RuleInvalid, Reason: werr.Error()}
		}
		return werr
	}
	if written.HoldReason == "" {
		if acc, aerr := g.svc.Access(sctx, p.Name); aerr != nil || acc.Mode != AccessFull {
			reason := holdNote(acc.Mode)
			if ok, herr := st.HoldWrite(sctx, written.Namespace, written.ID, actionID, reason); herr != nil || !ok {
				g.log.Error("memory gateway: write made while access changed could not be held for review", "action_id", actionID, "err", herr)
			} else {
				written.HoldReason, written.PromoteAt = reason, nil
			}
		}
	}
	undoable := true
	if aerr := g.undo.Activate(sctx, actionID); aerr != nil {
		// The item is staged; only the handle's state change failed.
		g.log.Error("memory gateway: item staged but its undo handle could not be activated; review manually", "action_id", actionID, "err", aerr)
		undoable = false
	}
	item := map[string]any{"id": written.ID, "store": op.store, "namespace": written.Namespace, "staged": true,
		"promote_at": written.PromoteAt, "created_at": written.CreatedAt}
	note := "staged: promoted to long-term memory at promote_at unless flagged; undoable (dropped) until then, NOT undoable after promotion"
	if written.HoldReason != "" {
		item["held_for_review"] = true
		item["hold_reason"] = written.HoldReason
		note = "staged and held for review (no promote_at yet): once the agent is back at full access it gets a review window, then is promoted unless flagged; undoable (dropped) until promotion"
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"action_id": actionID,
		"item":      item,
		"undo":      map[string]any{"kind": undo.KindMemoryStaging, "undoable": undoable, "note": note},
	})
	return nil
}

func (g *GatewayAdapter) query(ctx context.Context, p authz.Principal, st *PGStore, op *gwOp, actionID string, w http.ResponseWriter) error {
	q := SearchRequest{Namespace: op.namespace, Embedding: op.query.Embedding, Text: op.query.Text, Limit: op.query.Limit,
		IncludeEmbedding: op.query.IncludeEmbeddings}
	if op.query.IncludeOwnStaged == nil || *op.query.IncludeOwnStaged {
		q.StagedOf = p.Name
	}
	hits, err := st.Search(ctx, q)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			return &gateway.RefusedError{RuleID: RuleInvalid, Reason: err.Error()}
		}
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"action_id": actionID, "store": op.store, "namespace": op.namespace, "items": hits})
	return nil
}

func (g *GatewayAdapter) delete(ctx context.Context, p authz.Principal, st *PGStore, op *gwOp, actionID string, w http.ResponseWriter) error {
	it, err := st.DeleteItem(ctx, op.namespace, op.itemID)
	if errors.Is(err, ErrItemNotFound) {
		return &gateway.RefusedError{RuleID: RuleNotFound, Reason: fmt.Sprintf("no memory item %s in %s/%s: nothing deleted", op.itemID, op.store, op.namespace)}
	}
	if err != nil {
		return err
	}
	// Deleted and tombstoned. Record it and close the staging undo handle of
	// the write that staged it (nothing is left to undo).
	if rerr := g.svc.RecordDeleted(ctx, st.Key(), it, actionID, p.Name, p.Actor()); rerr != nil {
		g.log.Error("memory gateway: item deleted but not recorded", "action_id", actionID, "err", rerr)
		return fmt.Errorf("memory item %s was deleted but %w", it.ID, rerr)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"action_id": actionID, "deleted": it.ID, "store": op.store,
		"namespace": it.Namespace, "was_staged": it.Staged,
		"note": "deleted: NOT undoable, and restoring an older snapshot does not bring it back"})
	return nil
}
