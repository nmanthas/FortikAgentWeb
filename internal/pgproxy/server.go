// Package pgproxy is Fortik's PostgreSQL wire-protocol proxy. Agents connect
// to it as if it were Postgres; every statement is classified (internal/pgsql)
// and decided (decide.Decider) BEFORE it reaches the upstream database, and
// the decision is enforced on the wire. See README.md for the contract.
package pgproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"fortik/internal/broker/pgroles"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/secrets"
	"fortik/internal/shadow"
	"fortik/internal/undo"
)

const (
	startupTimeout = 30 * time.Second
	connectTimeout = 15 * time.Second
	actor          = "pgproxy"
)

// Server accepts agent connections and proxies them to configured upstreams.
type Server struct {
	cfg     config.PGProxyConfig
	undoCfg config.UndoConfig
	sec     secrets.Provider
	d       decide.Decider
	us      undo.Store
	log     *slog.Logger
	tlsCfg  *tls.Config
	now     func() time.Time
	roles   RoleBroker // nil: YAML upstreams only (Phase 1)
	shadow  shadow.TrafficRecorder

	legacyWarned sync.Map // upstream name -> struct{}: "legacy" warning logged

	mu       sync.Mutex
	closing  bool
	conns    map[net.Conn]struct{} // connections still in startup
	sessions map[*session]struct{}
	keys     map[uint32]*session // proxy-issued backend pid -> session
	wg       sync.WaitGroup
}

// RoleBroker issues per-agent upstream logins for integration-backed
// upstreams (postgres:<name>). *pgroles.Manager implements it.
type RoleBroker interface {
	// Connect logs in to the upstream as the agent's own role with a fresh
	// password. It returns pgroles.ErrUpstreamNotManaged when the upstream is
	// not an integration (the YAML upstream, if any, is used instead).
	Connect(ctx context.Context, agentID, instanceID, upstream string, runtime map[string]string) (*pgconn.PgConn, pgroles.Session, error)
	// AdminConnConfig returns a login as the integration's admin user.
	AdminConnConfig(ctx context.Context, upstream string, runtime map[string]string) (*pgconn.Config, pgroles.Upstream, error)
}

// Option configures optional Server behaviour.
type Option func(*Server)

// WithRoles enables integration-backed upstreams: an upstream configured as
// integration postgres:<name> (it wins over a YAML upstream of the same
// name) is reached as the agent's own role issued by rb.
func WithRoles(rb RoleBroker) Option { return func(s *Server) { s.roles = rb } }

// WithShadow records failed agent logins (unknown agent ids, unknown
// tokens for a known agent) as shadow-discovery traffic findings: the
// claimed user, a keyed hash prefix of the password, the client address and
// application_name only. The recorder must not block; nil disables it.
func WithShadow(r shadow.TrafficRecorder) Option { return func(s *Server) { s.shadow = r } }

// New validates the configuration and builds a Server.
func New(cfg config.PGProxyConfig, undoCfg config.UndoConfig, sec secrets.Provider, d decide.Decider, us undo.Store, log *slog.Logger, opts ...Option) (*Server, error) {
	if sec == nil || d == nil || us == nil {
		return nil, errors.New("pgproxy: secrets provider, decider and undo store are required")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.AgentTokensSecret == "" {
		cfg.AgentTokensSecret = "agent_tokens"
	}
	if cfg.PreQueryTimeout <= 0 {
		cfg.PreQueryTimeout = 3 * time.Second
	}
	if undoCfg.SnapshotRetention <= 0 {
		undoCfg.SnapshotRetention = 30 * 24 * time.Hour
	}
	s := &Server{
		cfg: cfg, undoCfg: undoCfg, sec: sec, d: d, us: us,
		log:      log.With("component", "pgproxy"),
		now:      time.Now,
		conns:    map[net.Conn]struct{}{},
		sessions: map[*session]struct{}{},
		keys:     map[uint32]*session{},
	}
	for _, o := range opts {
		o(s)
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, errors.New("pgproxy: tls_cert_file and tls_key_file must be set together")
	}
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("pgproxy: load TLS key pair: %w", err)
		}
		s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return s, nil
}

// ListenAndServe listens on cfg.Listen and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.cfg.Listen
	if addr == "" {
		addr = "127.0.0.1:6432"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("pgproxy: listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled, then stops
// accepting, closes every session and waits for them to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	shutdown := sync.OnceFunc(func() {
		_ = ln.Close()
		s.mu.Lock()
		s.closing = true
		for c := range s.conns {
			_ = c.Close()
		}
		for sess := range s.sessions {
			sess.close()
		}
		s.mu.Unlock()
	})
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		shutdown()
	}()
	defer close(stop)
	s.log.Info("pgproxy listening", "addr", ln.Addr().String())
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				shutdown()
				s.wg.Wait()
				return nil
			}
			if temporaryAcceptError(err) {
				// Like net/http: back off and keep serving (EMFILE, ENFILE,
				// ECONNABORTED, ...); existing sessions are unaffected.
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				s.log.Warn("accept failed; retrying", "err", err, "retry_in", delay)
				t := time.NewTimer(delay)
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
				}
				continue
			}
			// Fatal: stop serving and close every session before waiting.
			s.log.Error("accept failed; shutting down", "err", err)
			shutdown()
			s.wg.Wait()
			return fmt.Errorf("pgproxy: accept: %w", err)
		}
		delay = 0
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handleConn(ctx, conn)
		}()
	}
}

// temporaryAcceptError reports whether an Accept error is transient.
func temporaryAcceptError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ECONNRESET,
		syscall.ENOBUFS, syscall.ENOMEM, syscall.EAGAIN, syscall.EINTR, syscall.EPROTO} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func fatal(code, msg string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: msg}
}

func writeMsgs(conn net.Conn, msgs ...pgproto3.BackendMessage) error {
	var buf []byte
	var err error
	for _, m := range msgs {
		if buf, err = m.Encode(buf); err != nil {
			return err
		}
	}
	_, err = conn.Write(buf)
	return err
}

// handleConn runs connection setup and then the session.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(startupTimeout))
	be := pgproto3.NewBackend(conn, conn)
	var startup *pgproto3.StartupMessage
	for startup == nil {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			s.log.Debug("startup read failed", "err", err)
			return
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest:
			if s.tlsCfg == nil {
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return
				}
				continue
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return
			}
			tc := tls.Server(conn, s.tlsCfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				s.log.Debug("tls handshake failed", "err", err)
				return
			}
			conn = tc
			be = pgproto3.NewBackend(conn, conn)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.CancelRequest:
			s.forwardCancel(ctx, m.ProcessID, m.SecretKey)
			return
		case *pgproto3.StartupMessage:
			startup = &pgproto3.StartupMessage{ProtocolVersion: m.ProtocolVersion, Parameters: map[string]string{}}
			for k, v := range m.Parameters {
				startup.Parameters[k] = v
			}
		default:
			return
		}
	}

	params := startup.Parameters
	var unrecognized []string
	for k := range params {
		if strings.HasPrefix(k, "_pq_.") {
			unrecognized = append(unrecognized, k)
		}
	}
	if startup.ProtocolVersion != pgproto3.ProtocolVersion30 || len(unrecognized) > 0 {
		// We speak protocol 3.0 only.
		if err := writeMsgs(conn, &pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: 0, UnrecognizedOptions: unrecognized}); err != nil {
			return
		}
	}
	if r := strings.ToLower(params["replication"]); r != "" && r != "false" && r != "off" && r != "0" && r != "no" {
		_ = writeMsgs(conn, fatal("08P01", "fortik: replication connections are not supported"))
		return
	}
	agentID := params["user"]
	if agentID == "" {
		_ = writeMsgs(conn, fatal("28000", "fortik: no user (agent_id) specified in startup packet"))
		return
	}
	dbName := params["database"]
	if dbName == "" {
		dbName = agentID
	}
	instanceID := ""
	if app := params["application_name"]; strings.HasPrefix(app, "fortik:") {
		instanceID = strings.TrimPrefix(app, "fortik:")
		if !idPattern.MatchString(instanceID) {
			_ = writeMsgs(conn, fatal("28000", "fortik: invalid instance id in application_name (want fortik:<instance_id>, "+idPattern.String()+")"))
			return
		}
	}
	log := s.log.With("agent_id", agentID, "instance_id", instanceID, "database", dbName)

	// Authenticate the agent with its Fortik token.
	if err := writeMsgs(conn, &pgproto3.AuthenticationCleartextPassword{}); err != nil {
		return
	}
	if err := be.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	msg, err := be.Receive()
	if err != nil {
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		_ = writeMsgs(conn, fatal("08P01", "fortik: expected password message"))
		return
	}
	if err := s.authenticate(ctx, agentID, pw.Password); err != nil {
		log.Warn("agent authentication failed", "reason", err.Error())
		s.recordAuthFailure(conn, err, agentID, pw.Password, params["application_name"], dbName)
		_ = writeMsgs(conn, fatal("28P01", fmt.Sprintf("password authentication failed for user %q", agentID)))
		return
	}

	upName := dbName
	inst := instanceID
	if inst == "" {
		inst = "-"
	}
	runtime := map[string]string{"application_name": "fortik:" + agentID + ":" + inst}
	for k, v := range params {
		if forwardStartupParam[strings.ToLower(k)] {
			runtime[k] = v
		}
	}
	// The classifier parses UTF-8; pin the upstream encoding so Postgres
	// lexes exactly the bytes Fortik decided (see pgsql sessionGUCs).
	runtime["client_encoding"] = "UTF8"
	up, admin, pc, ferr := s.connectUpstream(ctx, log, agentID, instanceID, upName, runtime)
	if ferr != nil {
		_ = writeMsgs(conn, ferr)
		return
	}
	hj, err := pc.Hijack()
	if err != nil {
		pc.Close(context.Background())
		_ = writeMsgs(conn, fatal("08006", "fortik: upstream connection failed"))
		return
	}

	sess := newSession(s, conn, be, hj, agentID, instanceID, upName, up, admin, log)
	if !s.register(sess) {
		_ = hj.Conn.Close()
		_ = writeMsgs(conn, fatal("57P01", "fortik: proxy is shutting down"))
		return
	}
	defer s.unregister(sess)
	_ = conn.SetDeadline(time.Time{})

	hello := []pgproto3.BackendMessage{&pgproto3.AuthenticationOk{}}
	for k, v := range hj.ParameterStatuses {
		hello = append(hello, &pgproto3.ParameterStatus{Name: k, Value: v})
	}
	hello = append(hello,
		&pgproto3.BackendKeyData{ProcessID: sess.proxyPID, SecretKey: sess.proxyKey},
		&pgproto3.ReadyForQuery{TxStatus: hj.TxStatus})
	if err := writeMsgs(conn, hello...); err != nil {
		sess.close()
		return
	}
	log.Info("agent session started", "upstream", upName, "environment", up.Environment, "managed_role", admin != "")
	conn = nil // owned by the session now
	sess.run(ctx)
	log.Info("agent session ended")
}

// idPattern mirrors action.Action's id validation.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

// forwardStartupParam lists client startup parameters forwarded upstream.
// Anything else (notably "options", which can carry -c role=...) is dropped.
var forwardStartupParam = map[string]bool{
	"datestyle": true, "timezone": true, "intervalstyle": true,
	"extra_float_digits": true, "search_path": true, "statement_timeout": true,
	"lock_timeout": true, "idle_in_transaction_session_timeout": true, "bytea_output": true,
	"default_transaction_isolation": true, "client_min_messages": true,
}

// authenticate checks token against the agent_tokens secret, reloaded on
// every connection so tokens can be rotated without a restart.
func (s *Server) authenticate(ctx context.Context, agentID, token string) error {
	raw, err := s.sec.Get(ctx, s.cfg.AgentTokensSecret)
	if err != nil {
		return fmt.Errorf("agent token secret unavailable: %w", err)
	}
	var tokens map[string]string
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return errors.New("agent token secret is not valid JSON")
	}
	sum := sha256.Sum256([]byte(token))
	got := []byte(hex.EncodeToString(sum[:]))
	want, known := tokens[agentID]
	wantB := []byte(strings.ToLower(strings.TrimSpace(want)))
	if !known || len(wantB) != len(got) {
		// Compare against something anyway to keep timing uniform.
		subtle.ConstantTimeCompare(got, got)
		if !known {
			return errUnknownAgent
		}
		return errBadToken
	}
	if subtle.ConstantTimeCompare(got, wantB) != 1 {
		return errBadToken
	}
	return nil
}

var (
	errUnknownAgent = errors.New("unknown agent")
	errBadToken     = errors.New("bad token")
)

// recordAuthFailure reports a failed login with a well-formed password to
// shadow discovery (never the password itself).
func (s *Server) recordAuthFailure(conn net.Conn, err error, agentID, password, app, db string) {
	if s.shadow == nil || password == "" || len(password) > 512 {
		return
	}
	ev := shadow.TrafficEvent{Source: shadow.SourcePGProxy, AgentID: agentID, Host: shadow.HostOf(conn.RemoteAddr().String()),
		UserAgent: app, Detail: "database=" + db}
	switch {
	case errors.Is(err, errUnknownAgent):
		ev.Kind = shadow.KindUnknownAgent
	case errors.Is(err, errBadToken):
		ev.Kind, ev.TokenRef = shadow.KindUnknownToken, shadow.TokenRef(password)
	default:
		return // the token secret is unavailable: not a finding
	}
	s.shadow.RecordTraffic(ev)
}

func (s *Server) register(sess *session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return false
		}
		pid := binary.BigEndian.Uint32(b[:4]) & 0x7fffffff
		if pid == 0 || s.keys[pid] != nil {
			continue
		}
		sess.proxyPID = pid
		sess.proxyKey = append([]byte(nil), b[4:]...)
		s.keys[pid] = sess
		s.sessions[sess] = struct{}{}
		return true
	}
}

func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	delete(s.keys, sess.proxyPID)
	delete(s.sessions, sess)
	s.mu.Unlock()
}

// forwardCancel maps a proxy-issued key to the upstream backend and sends a
// real CancelRequest there with the upstream's key.
func (s *Server) forwardCancel(ctx context.Context, pid uint32, key []byte) {
	s.mu.Lock()
	sess := s.keys[pid]
	s.mu.Unlock()
	if sess == nil || subtle.ConstantTimeCompare(key, sess.proxyKey) != 1 {
		s.log.Debug("cancel request with unknown key ignored")
		return
	}
	if err := sess.onCancelRequest(ctx); err != nil {
		sess.log.Warn("forwarding cancel request failed", "err", err)
		return
	}
	sess.log.Info("cancel request handled")
}

// connectUpstream logs in to the upstream the agent asked for. An
// integration-backed upstream (postgres:<name>) is reached as the agent's own
// role with a fresh password, and admin is the integration's admin user. A
// YAML-only upstream uses its static user (Phase 1, "legacy") and admin is "".
// On failure it returns the FATAL error to send: 3D000 when the database is
// configured nowhere, 08004 when the upstream or the session is refused.
func (s *Server) connectUpstream(ctx context.Context, log *slog.Logger, agentID, instanceID, upName string, runtime map[string]string) (config.UpstreamConfig, string, *pgconn.PgConn, *pgproto3.ErrorResponse) {
	if s.roles != nil {
		pc, sess, err := s.roles.Connect(ctx, agentID, instanceID, upName, runtime)
		switch {
		case err == nil:
			return sess.Upstream.UpstreamConfig(sess.User), sess.Upstream.AdminUser, pc, nil
		case errors.Is(err, pgroles.ErrUpstreamNotManaged):
			// Not an integration: the YAML upstream below, if any.
		case errors.Is(err, pgroles.ErrNoAccess):
			log.Warn("upstream session refused: no access in the agent's postgres profile", "upstream", upName, "reason", err.Error())
			return config.UpstreamConfig{}, "", nil, fatal("08004",
				fmt.Sprintf("fortik: agent %q has no access to database %q (postgres access profile)", agentID, upName))
		case errors.Is(err, pgroles.ErrAgentBlocked):
			log.Warn("upstream session refused: agent control level", "upstream", upName, "reason", err.Error())
			return config.UpstreamConfig{}, "", nil, fatal("08004",
				fmt.Sprintf("fortik: agent %q may not open database sessions at its current control level", agentID))
		default:
			log.Error("upstream session refused", "upstream", upName, "err", err)
			return config.UpstreamConfig{}, "", nil, fatal("08004",
				fmt.Sprintf("fortik: database %q is not available (upstream unreachable or not configured correctly)", upName))
		}
	}
	up, ok := s.cfg.Upstreams[upName]
	if !ok {
		log.Warn("unknown database requested")
		return config.UpstreamConfig{}, "", nil, fatal("3D000", fmt.Sprintf("fortik: database %q is not configured in Fortik", upName))
	}
	if _, warned := s.legacyWarned.LoadOrStore(upName, struct{}{}); !warned {
		log.Warn("legacy upstream: agents share the static YAML user (no per-agent role); configure it as integration postgres:"+upName,
			"upstream", upName)
	}
	if up.Database == "" {
		up.Database = upName
	}
	if up.Port == 0 {
		up.Port = 5432
	}
	pcfg, err := ConnConfig(ctx, up, s.sec, runtime)
	if err != nil {
		log.Error("upstream config failed", "upstream", upName, "err", err)
		return config.UpstreamConfig{}, "", nil, fatal("08004", fmt.Sprintf("fortik: database %q is not available (upstream not configured correctly)", upName))
	}
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	pc, err := pgconn.ConnectConfig(cctx, pcfg)
	cancel()
	if err != nil {
		log.Error("upstream connect failed", "upstream", upName, "err", err)
		return config.UpstreamConfig{}, "", nil, fatal("08004", fmt.Sprintf("fortik: database %q is not available (upstream unreachable)", upName))
	}
	return up, "", pc, nil
}

// ConnConfig builds a pgconn config for a YAML upstream (password from the
// secret named by PasswordSecret). Shared with the undo executor.
func ConnConfig(ctx context.Context, up config.UpstreamConfig, sec secrets.Provider, runtime map[string]string) (*pgconn.Config, error) {
	password := ""
	if up.PasswordSecret != "" {
		pw, err := sec.Get(ctx, up.PasswordSecret)
		if err != nil {
			return nil, fmt.Errorf("upstream password secret: %w", err)
		}
		password = string(pw)
	}
	return pgroles.BuildConnConfig(up.Host, up.Port, up.Database, up.User, password, up.SSLMode, runtime)
}
