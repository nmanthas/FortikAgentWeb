package nsquickstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"fortik/internal/action"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

// KindRecord is the undo kind for a QuickStart update_record whose changed
// fields Fortik read (read_record) and stored before running it.
const KindRecord = "netsuite_quickstart_record"

// RecordUndoData is handle_json for KindRecord. The previous values are
// customer data: they are kept encrypted in the secret store under Secret,
// never in Postgres, and deleted after the undo or at expiry.
type RecordUndoData struct {
	Key        string          `json:"key,omitempty"` // the connection; empty in handles before multi-tenancy (the legacy key)
	RecordType string          `json:"record_type"`   // as the agent sent it (QuickStart ids are case-sensitive)
	RecordID   json.RawMessage `json:"record_id"`
	Fields     []string        `json:"fields"`
	Secret     string          `json:"secret"`
	ServerID   string          `json:"server_id"`
}

// EnableUndo turns on update snapshots (QuickStart Milestone 4).
func (s *Service) EnableUndo(us undo.Store, store secrets.Store, retention time.Duration) {
	s.undo, s.secrets, s.retention = us, store, retention
}

func snapshotSecret(actionID string) string {
	return "netsuite_quickstart_undo_" + strings.ToLower(actionID)
}

// prepareUndo reads the record through QuickStart (read_record) and keeps the
// current value of every field the update sets. Only plain values are
// snapshotted: a field that is missing from the read, or whose value is an
// object or a list, makes the snapshot fail, and the update is not run.
func (s *Service) prepareUndo(ctx context.Context, st Settings, a action.Action, args json.RawMessage, actor string) error {
	if s.undo == nil || s.secrets == nil {
		return errors.New("undo snapshots are not enabled in this deployment")
	}
	var in struct {
		RecordType  string                     `json:"recordType"`
		ID          json.RawMessage            `json:"id"`
		FieldValues map[string]json.RawMessage `json:"fieldValues"`
	}
	if err := json.Unmarshal(args, &in); err != nil || in.RecordType == "" || len(in.ID) == 0 || len(in.FieldValues) == 0 {
		return errors.New("the update does not name a record type, id and fields")
	}
	readArgs, _ := json.Marshal(map[string]any{"recordType": in.RecordType, "id": in.ID})
	res, err := s.callTool(ctx, st, "read_record", readArgs)
	if err != nil {
		return fmt.Errorf("read before update: %w", err)
	}
	if res.IsError {
		return errors.New("read before update: QuickStart reported an error reading the record")
	}
	current, err := recordValues(res.Raw)
	if err != nil {
		return fmt.Errorf("read before update: %w", err)
	}
	prev := map[string]json.RawMessage{}
	var fields []string
	for k := range in.FieldValues {
		v, ok := current[k]
		if !ok {
			return fmt.Errorf("field %q is not in the record as read, so its previous value is unknown", clip(k, 64))
		}
		if !plain(v) {
			return fmt.Errorf("field %q holds a structured value that Fortik does not snapshot", clip(k, 64))
		}
		prev[k] = v
		fields = append(fields, k)
	}
	blob, _ := json.Marshal(prev)
	name := snapshotSecret(a.ActionID)
	if err := s.secrets.Put(ctx, name, blob); err != nil {
		return fmt.Errorf("store snapshot: %w", err)
	}
	data, _ := json.Marshal(RecordUndoData{Key: st.Key, RecordType: in.RecordType, RecordID: in.ID, Fields: sortStrings(fields), Secret: name, ServerID: serverOf(a)})
	h := undo.Handle{ActionID: a.ActionID, AgentID: a.AgentID, Kind: KindRecord, Data: data, ExpiresAt: time.Now().Add(s.retention)}
	if err := s.undo.Prepare(ctx, h, actor); err != nil {
		_ = s.secrets.Delete(context.WithoutCancel(ctx), name)
		return fmt.Errorf("prepare undo: %w", err)
	}
	return nil
}

func (s *Service) activateUndo(ctx context.Context, actionID string) error {
	return s.undo.Activate(ctx, actionID)
}

func (s *Service) failUndo(ctx context.Context, actionID, note string) {
	if s.undo == nil {
		return
	}
	_ = s.undo.Fail(ctx, actionID, note)
	_ = s.secrets.Delete(ctx, snapshotSecret(actionID))
}

// recordValues finds the record's body values in a read_record result:
// structuredContent.fieldValues, or the same object as JSON text content.
func recordValues(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var res struct {
		Structured json.RawMessage `json:"structuredContent"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, errors.New("unreadable read_record result")
	}
	candidates := []json.RawMessage{res.Structured}
	for _, c := range res.Content {
		if c.Type == "text" && strings.HasPrefix(strings.TrimSpace(c.Text), "{") {
			candidates = append(candidates, json.RawMessage(c.Text))
		}
	}
	for _, c := range candidates {
		var obj struct {
			FieldValues map[string]json.RawMessage `json:"fieldValues"`
			Record      *struct {
				FieldValues map[string]json.RawMessage `json:"fieldValues"`
			} `json:"record"`
		}
		if len(c) == 0 || json.Unmarshal(c, &obj) != nil {
			continue
		}
		if obj.FieldValues != nil {
			return obj.FieldValues, nil
		}
		if obj.Record != nil && obj.Record.FieldValues != nil {
			return obj.Record.FieldValues, nil
		}
	}
	return nil, errors.New("the read_record result has no fieldValues Fortik recognises")
}

func plain(v json.RawMessage) bool {
	v = bytes.TrimSpace(v)
	return len(v) > 0 && v[0] != '{' && v[0] != '['
}

func serverOf(a action.Action) string {
	s, _ := a.Target["server_id"].(string)
	return s
}

func sortStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// UndoExecutor writes snapshotted values back (POST /v1/undo/{action_id}).
type UndoExecutor struct{ s *Service }

var _ undo.Executor = (*UndoExecutor)(nil)

// UndoExecutor returns the executor for KindRecord.
func (s *Service) UndoExecutor() *UndoExecutor { return &UndoExecutor{s: s} }

func (e *UndoExecutor) Kinds() []string { return []string{KindRecord} }

// Undo calls update_record with the previous values. QuickStart has no
// conditional update, so this is last-writer-wins on exactly those fields:
// a change made to them after the update is overwritten (the result says so).
func (e *UndoExecutor) Undo(ctx context.Context, h undo.Handle) (map[string]any, error) {
	var d RecordUndoData
	if err := json.Unmarshal(h.Data, &d); err != nil || d.RecordType == "" || len(d.RecordID) == 0 || d.Secret == "" {
		return nil, errors.New("netsuite quickstart undo: incomplete handle")
	}
	key := d.Key
	if key == "" {
		key = IntegrationKey
	}
	st, cat, err := e.s.current(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("netsuite quickstart undo: %w", err)
	}
	if d.ServerID != "" && cat.ServerID != d.ServerID {
		return nil, fmt.Errorf("netsuite quickstart undo: the integration now points at %s, the snapshot is from %s: refused", cat.ServerID, d.ServerID)
	}
	blob, err := e.s.secrets.Get(ctx, d.Secret)
	if err != nil {
		return nil, fmt.Errorf("netsuite quickstart undo: snapshot unavailable: %w", err)
	}
	args, _ := json.Marshal(map[string]any{"recordType": d.RecordType, "id": d.RecordID, "fieldValues": json.RawMessage(blob)})
	res, err := e.s.callTool(ctx, st, "update_record", args)
	if err != nil {
		return nil, fmt.Errorf("netsuite quickstart undo: %w (it is not known whether QuickStart applied it; check the record)", err)
	}
	if res.IsError {
		return nil, fmt.Errorf("netsuite quickstart undo: QuickStart refused the restore: %s", clip(resultText(res.Raw), 200))
	}
	_ = e.s.secrets.Delete(ctx, d.Secret)
	return map[string]any{"record_type": d.RecordType, "record_id": string(d.RecordID), "fields_restored": d.Fields,
		"note": "previous values written back with update_record (last writer wins: changes made to these fields after the update are overwritten)"}, nil
}

func resultText(raw json.RawMessage) string {
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(raw, &res)
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
		b.WriteByte(' ')
	}
	return strings.TrimSpace(b.String())
}
