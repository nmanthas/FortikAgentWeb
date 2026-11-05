package saasrest

// Salesforce Agent API (Agentforce agents) through Fortik's gateway.
//
// Agents talk to an Agentforce agent with Salesforce's Agent API
// (https://api.salesforce.com/einstein/ai-agent/v1): start a session for an
// agent (BotDefinition id), send messages to the session, end it. Fortik
// governs each call like any other Salesforce call (system salesforce,
// transport rest_api, target.api agent_api) and forwards it with a token it
// holds, so the agent never receives Salesforce credentials:
//
//	POST   /gw/salesforce/einstein/ai-agent/v1/agents/{agentId}/sessions    agent_session_start  READ
//	POST   /gw/salesforce/einstein/ai-agent/v1/sessions/{sessionId}/messages agent_message        EXECUTE
//	DELETE /gw/salesforce/einstein/ai-agent/v1/sessions/{sessionId}          agent_session_end    READ
//
// A message can make the Agentforce agent act inside Salesforce (create a
// case, update a record) where Fortik cannot see or undo it, so it is an
// EXECUTE: held for approval (POL-1214) unless the access profile says
// agentforce_messages "allow". The Agentforce agents a Fortik agent may
// talk to are listed in its profile (agentforce_agents, POL-1213).
//
// Sessions are bound to the Fortik agent that started them through Fortik:
// a message to, or the end of, a session Fortik did not start for the same
// agent is refused (UNKNOWN). The binding is kept in memory; after a Fortik
// restart, agents start a new session.
//
// Request shapes follow Salesforce's own client (@salesforce/agents,
// ProductionAgent): the session start body carries externalSessionKey,
// instanceConfig.endpoint (the org's My Domain), streamingCapabilities and
// bypassUser; a message is {message:{sequenceId,type:"Text",text},variables};
// the end is a DELETE with x-session-end-reason. Streaming
// (/messages/stream) is not supported through Fortik.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"fortik/internal/authz"
	"fortik/internal/gateway"
)

const (
	// AgentAPIPrefix is the Agent API's path below the gateway's /gw/salesforce.
	AgentAPIPrefix = "/einstein/ai-agent/v1/"
	// DefaultAgentAPIURL is Salesforce's Agent API host.
	DefaultAgentAPIURL = "https://api.salesforce.com"
	// AgentAPITimeout bounds one Agent API call (Salesforce answers within
	// 120 s or returns an error).
	AgentAPITimeout = 130 * time.Second

	opAgentStart   = "agent_session_start"
	opAgentMessage = "agent_message"
	opAgentEnd     = "agent_session_end"

	agentSessionTTL  = 24 * time.Hour
	maxAgentSessions = 5000
	maxMessageChars  = 20000
)

var (
	agentStartRe   = regexp.MustCompile(`^/einstein/ai-agent/v1/agents/([A-Za-z0-9]{15}|[A-Za-z0-9]{18})/sessions$`)
	agentMessageRe = regexp.MustCompile(`^/einstein/ai-agent/v1/sessions/([A-Za-z0-9-]{8,80})/messages$`)
	agentSessionRe = regexp.MustCompile(`^/einstein/ai-agent/v1/sessions/([A-Za-z0-9-]{8,80})$`)
	agentStreamRe  = regexp.MustCompile(`^/einstein/ai-agent/v1/sessions/[^/]+/messages/stream$`)
	endReasons     = map[string]bool{"UserRequest": true, "Transfer": true, "Expiration": true, "Error": true, "Other": true}
)

// IsAgentAPIPath reports whether a /gw/salesforce path is an Agent API call.
func IsAgentAPIPath(path string) bool { return strings.HasPrefix(path, AgentAPIPrefix) }

// agentSession binds a Salesforce Agent API session to the Fortik agent and
// connection that started it.
type agentSession struct {
	owner, sfAgent, key string
	started             time.Time
}

type agentSessions struct {
	mu sync.Mutex
	m  map[string]agentSession
}

func (s *agentSessions) put(id string, v agentSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]agentSession{}
	}
	now := time.Now()
	for k, x := range s.m {
		if now.Sub(x.started) > agentSessionTTL {
			delete(s.m, k)
		}
	}
	for len(s.m) >= maxAgentSessions { // drop the oldest
		oldest, at := "", now
		for k, x := range s.m {
			if x.started.Before(at) {
				oldest, at = k, x.started
			}
		}
		delete(s.m, oldest)
	}
	s.m[id] = v
}

func (s *agentSessions) get(id string) (agentSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[id]
	if ok && time.Since(v.started) > agentSessionTTL {
		delete(s.m, id)
		return agentSession{}, false
	}
	return v, ok
}

func (s *agentSessions) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

func (s *agentSessions) dropKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.key == key {
			delete(s.m, k)
		}
	}
}

// agentMessage is the text of a message body Fortik accepts: Salesforce's
// {message:{text,...}} or the short form {text}.
type agentMessage struct {
	Message *struct {
		SequenceID json.Number `json:"sequenceId"`
		Type       string      `json:"type"`
		Text       string      `json:"text"`
	} `json:"message"`
	Text      string          `json:"text"`
	Variables json.RawMessage `json:"variables"`
}

func parseAgentMessage(body []byte) (text string, seq json.Number, vars json.RawMessage, err error) {
	var m agentMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return "", "", nil, errors.New(`the body must be JSON: {"message":{"type":"Text","text":"..."}}`)
	}
	text = m.Text
	if m.Message != nil {
		if m.Message.Type != "" && m.Message.Type != "Text" {
			return "", "", nil, errors.New("only Text messages are supported")
		}
		text, seq = m.Message.Text, m.Message.SequenceID
	}
	if strings.TrimSpace(text) == "" {
		return "", "", nil, errors.New("the message text is empty")
	}
	if len(text) > maxMessageChars {
		return "", "", nil, fmt.Errorf("the message is longer than %d characters", maxMessageChars)
	}
	if len(m.Variables) > 0 && !bytes.HasPrefix(bytes.TrimSpace(m.Variables), []byte("[")) && string(bytes.TrimSpace(m.Variables)) != "null" {
		return "", "", nil, errors.New("variables must be a list")
	}
	return text, seq, m.Variables, nil
}

// mapAgentAPI names an Agent API call. ok=false (with a reason) refuses it.
func (a *Adapter) mapAgentAPI(p authz.Principal, method, path string, body []byte, conn restConn) (Request, map[string]any, string) {
	t := map[string]any{"api": "agent_api", "object": "agentforce_agent"}
	switch {
	case agentStreamRe.MatchString(path):
		return Request{}, nil, "streaming Agent API calls are not supported through Fortik: send to /messages"
	case method == http.MethodPost && agentStartRe.MatchString(path):
		id := agentStartRe.FindStringSubmatch(path)[1]
		t["agentforce_agent"] = id
		return Request{Operation: opAgentStart, Object: "agentforce_agent", RecordID: id}, t, ""
	case method == http.MethodPost && agentMessageRe.MatchString(path):
		sid := agentMessageRe.FindStringSubmatch(path)[1]
		sess, reason := a.ownSession(p, sid, conn)
		if reason != "" {
			return Request{}, nil, reason
		}
		text, _, _, err := parseAgentMessage(body)
		if err != nil {
			return Request{}, nil, "message refused: " + err.Error()
		}
		sum := sha256.Sum256([]byte(text))
		t["agentforce_agent"], t["session_id"] = sess.sfAgent, sid
		t["message_sha256"] = hex.EncodeToString(sum[:])
		t["message_preview"] = clip(strings.Join(strings.Fields(text), " "), 200)
		t["message_chars"] = len([]rune(text))
		return Request{Operation: opAgentMessage, Object: "agentforce_agent", RecordID: sid}, t, ""
	case method == http.MethodDelete && agentSessionRe.MatchString(path):
		sid := agentSessionRe.FindStringSubmatch(path)[1]
		sess, reason := a.ownSession(p, sid, conn)
		if reason != "" {
			return Request{}, nil, reason
		}
		t["agentforce_agent"], t["session_id"] = sess.sfAgent, sid
		return Request{Operation: opAgentEnd, Object: "agentforce_agent", RecordID: sid}, t, ""
	}
	return Request{}, nil, "this Agent API call is not one Fortik governs (start a session, send a message, end a session)"
}

func (a *Adapter) ownSession(p authz.Principal, sid string, conn restConn) (agentSession, string) {
	sess, ok := a.s.sessions.get(sid)
	if !ok || sess.owner != p.Name {
		return sess, "session " + clip(sid, 80) + " was not started through Fortik by this agent (or Fortik restarted): start a new session"
	}
	if sess.key != conn.key {
		return sess, "session " + clip(sid, 80) + " belongs to another Salesforce connection"
	}
	return sess, ""
}

// agentSettings are the credentials Fortik uses for the Agent API: the
// connection's own, or a separate Agent API app when one is configured.
func agentSettings(st Settings) Settings {
	if st.AgentClientID == "" {
		return st
	}
	ag := st
	ag.Key = st.Key + "#agent_api"
	ag.Auth, ag.ClientID, ag.ClientSecret = "client_credentials", st.AgentClientID, st.AgentClientSecret
	return ag
}

// forwardAgentAPI runs an allowed Agent API call.
func (a *Adapter) forwardAgentAPI(ctx context.Context, p authz.Principal, m Request, st Settings, body []byte, w http.ResponseWriter, r *http.Request) error {
	base := st.AgentAPIURL
	target := base + m.Path
	if why := a.s.guard.Refused(a.system, target); why != "" {
		return &gateway.RefusedError{RuleID: RuleRefused, Reason: "Agent API URL not permitted: " + why}
	}
	ag := agentSettings(st)
	auth, err := a.s.Token(ctx, ag)
	if err != nil {
		return &gateway.RefusedError{RuleID: RuleRefused, Reason: "Fortik could not authenticate to the Salesforce Agent API: " + clip(err.Error(), 160)}
	}
	hdr := http.Header{"Accept": {"application/json"}}
	var out []byte
	switch m.Operation {
	case opAgentStart:
		if out, err = startBody(body, st.Base); err != nil {
			return &gateway.RefusedError{RuleID: RuleRefused, Reason: "session start refused: " + err.Error()}
		}
		hdr.Set("Content-Type", "application/json")
	case opAgentMessage:
		text, seq, vars, err := parseAgentMessage(body)
		if err != nil {
			return &gateway.RefusedError{RuleID: RuleRefused, Reason: "message refused: " + err.Error()}
		}
		if seq == "" {
			seq = json.Number(fmt.Sprint(time.Now().UnixMilli()))
		}
		if len(vars) == 0 || string(bytes.TrimSpace(vars)) == "null" {
			vars = json.RawMessage("[]")
		}
		out, _ = json.Marshal(map[string]any{"message": map[string]any{"sequenceId": seq, "type": "Text", "text": text}, "variables": vars})
		hdr.Set("Content-Type", "application/json")
	case opAgentEnd:
		reason := r.Header.Get("X-Session-End-Reason")
		if !endReasons[reason] {
			reason = "UserRequest"
		}
		hdr.Set("X-Session-End-Reason", reason)
	}
	cctx, cancel := context.WithTimeout(ctx, AgentAPITimeout)
	defer cancel()
	resp, err := a.s.sendWith(cctx, a.s.agentHTTP, auth, m.Method, target, out, hdr)
	if err != nil {
		return fmt.Errorf("salesforce agent api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		a.s.Drop(ag.Key)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	switch {
	case ok && m.Operation == opAgentStart:
		var sr struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(b, &sr) == nil && agentSessionID.MatchString(sr.SessionID) {
			a.s.sessions.put(sr.SessionID, agentSession{owner: p.Name, sfAgent: m.RecordID, key: m.Key, started: time.Now()})
		}
	case m.Operation == opAgentEnd && (ok || resp.StatusCode == http.StatusNotFound):
		a.s.sessions.drop(m.RecordID)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(b)
	return nil
}

var agentSessionID = regexp.MustCompile(`^[A-Za-z0-9-]{8,80}$`)

// startBody completes a session start request: Fortik always names its own
// org (instanceConfig.endpoint = the connection's My Domain) and fills the
// fields Salesforce requires when the agent left them out.
func startBody(body []byte, myDomain string) ([]byte, error) {
	in := map[string]any{}
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&in); err != nil {
			return nil, errors.New("the body must be a JSON object (or empty)")
		}
	}
	out := map[string]any{}
	if k, ok := in["externalSessionKey"].(string); ok && agentSessionID.MatchString(k) {
		out["externalSessionKey"] = k
	} else {
		out["externalSessionKey"] = newUUID()
	}
	out["instanceConfig"] = map[string]any{"endpoint": myDomain}
	if sc, ok := in["streamingCapabilities"].(map[string]any); ok {
		out["streamingCapabilities"] = sc
	} else {
		out["streamingCapabilities"] = map[string]any{"chunkTypes": []string{"Text"}}
	}
	if b, ok := in["bypassUser"].(bool); ok {
		out["bypassUser"] = b
	} else {
		out["bypassUser"] = true
	}
	if v, ok := in["variables"].([]any); ok {
		out["variables"] = v
	}
	return json.Marshal(out)
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (s *Service) sendWith(ctx context.Context, c *http.Client, auth, method, target string, body []byte, hdr http.Header) (*http.Response, error) {
	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", auth)
	return c.Do(req)
}

// --- Test connection: what the Agent API needs ------------------------------

var agentAPIScopes = []string{"chatbot_api", "sfap_api"}

// probeAgentAPI reports (read-only) the org's Agentforce agents and whether
// the Agent API token looks usable. It never starts a session and never
// fails the REST connection's check.
func (s *Service) probeAgentAPI(ctx context.Context, st Settings, restAuth string) map[string]any {
	out := map[string]any{"endpoint": st.AgentAPIURL, "agent_endpoint_path": "/gw/salesforce" + AgentAPIPrefix}
	if st.AgentClientID != "" {
		out["credentials"] = "separate Agent API app"
	} else {
		out["credentials"] = "the REST connection's app"
	}
	if why := s.guard.Refused(st.System, st.AgentAPIURL); why != "" {
		out["status"], out["detail"] = "not_ready", "Agent API URL not permitted: "+why
		return out
	}
	// Agents in the org (BotDefinition), read with the REST token.
	q := "SELECT Id, DeveloperName, MasterLabel, AgentType FROM BotDefinition ORDER BY MasterLabel LIMIT 50"
	code, b, err := s.get(ctx, st, restAuth, "/services/data/v"+st.APIVersion+"/query?q="+url.QueryEscape(q), "application/json")
	if err == nil && code == http.StatusBadRequest { // AgentType is not in every API version
		q = "SELECT Id, DeveloperName, MasterLabel FROM BotDefinition ORDER BY MasterLabel LIMIT 50"
		code, b, err = s.get(ctx, st, restAuth, "/services/data/v"+st.APIVersion+"/query?q="+url.QueryEscape(q), "application/json")
	}
	switch {
	case err != nil:
		out["agents_detail"] = "could not list agents: " + clip(err.Error(), 160)
	case code != http.StatusOK:
		out["agents_detail"] = "could not list agents (BotDefinition): " + sfError(code, b)
	default:
		var qr struct {
			Records []struct {
				ID            string `json:"Id"`
				DeveloperName string `json:"DeveloperName"`
				MasterLabel   string `json:"MasterLabel"`
				AgentType     string `json:"AgentType"`
			} `json:"records"`
		}
		_ = json.Unmarshal(b, &qr)
		agents := make([]map[string]string, 0, len(qr.Records))
		for _, r := range qr.Records {
			a := map[string]string{"id": clip(r.ID, 18), "name": clip(r.MasterLabel, 80), "api_name": clip(r.DeveloperName, 80)}
			if r.AgentType != "" {
				a["type"] = clip(r.AgentType, 60)
			}
			agents = append(agents, a)
		}
		out["agents"] = agents
	}
	// The Agent API token: requested now, inspected (never stored or shown).
	ag := agentSettings(st)
	t, err := s.authenticate(ctx, ag)
	if err != nil {
		out["status"], out["detail"] = "not_ready", "Agent API token request failed: "+clip(err.Error(), 200)
		return out
	}
	format, scopes := inspectToken(strings.TrimPrefix(t.header, "Bearer "))
	out["token_format"] = format
	if format != "jwt" {
		out["status"] = "not_ready"
		out["detail"] = "the app issues opaque tokens: the Agent API needs JWT-based access tokens (in the External Client App's OAuth policies, enable \"Issue JSON Web Token (JWT)-based access tokens for named users\")"
		return out
	}
	if scopes != nil {
		out["token_scopes"] = scopes
		var missing []string
		for _, want := range agentAPIScopes {
			if !contains(scopes, want) {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			out["status"] = "not_ready"
			out["detail"] = "the token lacks the scope(s) " + strings.Join(missing, ", ") + ": add them to the app's OAuth scopes"
			return out
		}
	}
	if ag.Key != st.Key { // cache the separate app's token for the gateway
		t.version = st.Version
		s.mu.Lock()
		s.tokens[ag.Key] = t
		s.mu.Unlock()
	}
	out["status"] = "ready"
	out["detail"] = "a JWT access token was issued for the Agent API; no session was started. If a session start returns 404, check that the agent is Active, has a topic, and is not of type Agentforce (Default)"
	return out
}

// inspectToken tells a JWT from an opaque token and reads its scope claim
// (unverified: only to explain a misconfiguration).
func inspectToken(tok string) (string, []string) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "opaque", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "opaque", nil
	}
	var claims struct {
		Scope any `json:"scope"`
		Scp   any `json:"scp"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "opaque", nil
	}
	var scopes []string
	for _, c := range []any{claims.Scope, claims.Scp} {
		switch v := c.(type) {
		case string:
			scopes = append(scopes, strings.Fields(v)...)
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					scopes = append(scopes, s)
				}
			}
		}
	}
	if scopes == nil {
		return "jwt", nil
	}
	sort.Strings(scopes)
	return "jwt", scopes
}
