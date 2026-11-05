package nsquickstart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"fortik/internal/alerts"
	"fortik/internal/integrations"
)

// Alert kinds raised by the background check.
const (
	AlertConnection   = "quickstart_connection"    // the connection stopped working
	AlertTokenExpiry  = "quickstart_token_expiry"  // the token expires within 7 days, or has expired
	AlertToolsChanged = "quickstart_tools_changed" // the server's tools or their schemas changed
)

// WorkerActor is the actor of background checks in the Diary.
const WorkerActor = "system:netsuite_quickstart"

// Worker re-checks the connection every interval (initialize + tools/list,
// never a tool call), so a revoked or expired token, a disabled MCP server or
// a changed tool schema is noticed without anyone clicking Test connection.
// It raises alerts (deduplicated while open) for a broken connection, a token
// close to its entered expiry date, and changed tools. A changed tool list is
// recorded first, so agents' calls are validated against the new schemas
// (and refused while the list is not current).
func (s *Service) Worker(ctx context.Context, every time.Duration, raiser alerts.Raiser) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.Tick(ctx, raiser); err != nil {
			s.log.Warn("netsuite mcp: background check", "err", err)
		}
	}
}

// Tick runs one background check of every NetSuite MCP connection
// (exported for tests).
func (s *Service) Tick(ctx context.Context, raiser alerts.Raiser) error {
	var firstErr error
	for _, key := range s.mcpKeys(ctx) {
		if err := s.tickKey(ctx, key, raiser); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", key, err)
		}
	}
	return firstErr
}

func (s *Service) tickKey(ctx context.Context, key string, raiser alerts.Raiser) error {
	row, err := s.store.GetIntegration(ctx, key)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return nil
	}
	if err != nil {
		return err
	}
	name := row.IntegrationID
	before, err := s.Status(ctx, key)
	if err != nil {
		return err
	}
	// Token expiry (from the date the administrator entered; QuickStart).
	if t := before.Token; t.DaysLeft != nil && *t.DaysLeft <= 7 {
		sev, what := alerts.SevWarning, fmt.Sprintf("expires in %d day(s), on %s", *t.DaysLeft, t.ExpiresOn)
		if *t.DaysLeft < 0 {
			sev, what = alerts.SevHigh, "expired on "+t.ExpiresOn
		}
		s.raise(ctx, raiser, alerts.Alert{Kind: AlertTokenExpiry, Severity: sev, DedupKey: AlertTokenExpiry + ":" + key + ":" + t.ExpiresOn,
			Summary: "NetSuite QuickStart token of " + name + " " + what + ": create a new token in QuickStart and rotate it in Integrations",
			Details: details(map[string]any{"connection": key, "integration_id": name, "expires_on": t.ExpiresOn, "days_left": *t.DaysLeft})})
	}
	select {
	case s.running <- struct{}{}:
	default:
		return nil // a manual check is running
	}
	resolved, rerr := s.store.Resolve(ctx, key)
	var cerr error
	start := time.Now()
	if rerr == nil {
		row = resolved.Integration
		cerr = s.check(ctx, resolved, WorkerActor)
	} else {
		cerr = rerr
	}
	<-s.running
	res := integrations.TestResult{OK: cerr == nil, Duration: time.Since(start)}
	if cerr != nil {
		res.Error = integrations.Sanitize(cerr.Error(), resolved.Secrets)
	}
	if _, err := s.store.RecordTest(ctx, key, row.UpdatedAt, res, WorkerActor); err != nil && !errors.Is(err, integrations.ErrChanged) {
		return err
	}
	after, err := s.Status(ctx, key)
	if err != nil {
		return err
	}
	if after.State != StateConnected && after.State != StateSavedNotTested {
		s.raise(ctx, raiser, alerts.Alert{Kind: AlertConnection, Severity: alerts.SevHigh, DedupKey: AlertConnection + ":" + key + ":" + after.State,
			Summary: "NetSuite MCP connection of " + name + ": " + after.StateLabel + " (" + clip(after.Detail, 200) + "); agents' calls through it may fail until it is fixed",
			Details: details(map[string]any{"connection": key, "integration_id": name, "state": after.State, "previous_state": before.State})})
	}
	if before.ToolsHash != "" && after.ToolsHash != "" && before.ToolsHash != after.ToolsHash {
		s.raise(ctx, raiser, alerts.Alert{Kind: AlertToolsChanged, Severity: alerts.SevWarning, DedupKey: AlertToolsChanged + ":" + key + ":" + after.ToolsHash,
			Summary: fmt.Sprintf("NetSuite MCP server of %s changed its tools (%d now): review the tool list and its mapping", name, after.ToolCount),
			Details: details(map[string]any{"connection": key, "integration_id": name, "tools_hash": after.ToolsHash, "previous_tools_hash": before.ToolsHash, "tool_count": after.ToolCount})})
	}
	return nil
}

func (s *Service) raise(ctx context.Context, raiser alerts.Raiser, a alerts.Alert) {
	if raiser == nil {
		return
	}
	if _, err := raiser.Raise(ctx, a); err != nil {
		s.log.Error("netsuite mcp: raise alert", "kind", a.Kind, "err", err)
	}
}

func details(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
