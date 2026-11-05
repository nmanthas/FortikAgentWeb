package nsquickstart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/integrations"
	"fortik/internal/mcpclient"
)

// SessionMaxAge bounds how long one upstream MCP session is reused.
const SessionMaxAge = 10 * time.Minute

// upstream keeps one MCP session to QuickStart for the current settings. The
// token is read from the integration (secret store) when a session opens and
// is held only inside the client of that session.
type upstream struct {
	mu      sync.Mutex
	sess    *mcpclient.Session
	version time.Time
	token   string // the credential the session was opened with
}

func (u *upstream) drop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.sess != nil {
		go u.sess.Close()
		u.sess = nil
	}
}

func (s *Service) session(ctx context.Context, st Settings, fresh bool) (*mcpclient.Session, error) {
	u := s.up(st.Key)
	u.mu.Lock()
	defer u.mu.Unlock()
	if !fresh && u.sess != nil && u.version.Equal(st.Version) && u.token == st.Token && time.Since(u.sess.Opened) < SessionMaxAge {
		return u.sess, nil
	}
	if u.sess != nil {
		go u.sess.Close()
		u.sess = nil
	}
	c := &mcpclient.Client{HTTP: s.callHTTP, Endpoint: st.Endpoint, Token: st.Token, ClientName: "fortik", ClientVersion: s.version}
	sess, err := c.Open(ctx)
	if err != nil {
		return nil, err
	}
	u.sess, u.version, u.token = sess, st.Version, st.Token
	return sess, nil
}

// callTool runs one tools/call on QuickStart. A call is never repeated after
// the server may have processed it; only an expired session (the server says
// it did not process the request) is re-opened once.
func (s *Service) callTool(ctx context.Context, st Settings, tool string, args json.RawMessage) (*mcpclient.ToolResult, error) {
	if reason := s.endpointRefused(ctx, st.Endpoint, st.System); reason != "" {
		return nil, &mcpclient.Error{Kind: StateNotPermitted, Step: "tools/call", Detail: reason}
	}
	if err := s.bearer(ctx, &st); err != nil {
		return nil, &mcpclient.Error{Kind: mcpclient.KindAuthFailed, Step: "initialize", Detail: err.Error()}
	}
	sess, err := s.session(ctx, st, false)
	if err != nil {
		return nil, err
	}
	res, err := sess.CallTool(ctx, tool, args)
	if mcpclient.Expired(err) {
		if sess, err = s.session(ctx, st, true); err != nil {
			return nil, err
		}
		res, err = sess.CallTool(ctx, tool, args)
	}
	return res, err
}

// current returns a connection's settings (with the PAT; OAuth tokens are
// fetched by bearer) and the tool catalog of its last successful check.
func (s *Service) current(ctx context.Context, key string) (Settings, Catalog, error) {
	r, err := s.store.Get(ctx, key)
	if err != nil {
		return Settings{}, Catalog{}, err
	}
	st, err := settingsFrom(r)
	if err != nil {
		return Settings{}, Catalog{}, err
	}
	cat := Catalog{Tools: map[string]storedTool{}, Key: st.Key, System: st.System, IntegrationID: st.IntegrationID}
	var (
		version   time.Time
		state     string
		name      string
		toolsRaw  []byte
		succeeded *time.Time
	)
	err = s.pool.QueryRow(ctx, `SELECT config_version, state, server_name, tools, last_success_at FROM mcp_connections WHERE integration_key = $1`,
		key).Scan(&version, &state, &name, &toolsRaw, &succeeded)
	if errors.Is(err, pgx.ErrNoRows) {
		cat.ServerID = serverID("", st.Endpoint)
		return st, cat, nil
	}
	if err != nil {
		return Settings{}, Catalog{}, fmt.Errorf("netsuite mcp: tool catalog: %w", err)
	}
	var tools []storedTool
	_ = json.Unmarshal(toolsRaw, &tools)
	for _, t := range tools {
		cat.Tools[t.Name] = t
	}
	cat.ServerID = serverID(name, st.Endpoint)
	cat.Current = succeeded != nil && version.Equal(st.Version) && (state == StateConnected || state == StateConnectedLimit)
	return st, cat, nil
}

// notConfigured reports whether err means the integration cannot be used.
func notConfigured(err error) bool { return errors.Is(err, integrations.ErrNotConfigured) }
