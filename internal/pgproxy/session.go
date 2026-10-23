package pgproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"fortik/internal/config"
)

const (
	clientBufSize   = 64 * 1024
	upstreamBufSize = 64 * 1024
	flushInterval   = 10 * time.Millisecond
)

var errSessionClosed = errors.New("pgproxy: session closed")

// batch is one unit of upstream work that ends with a ReadyForQuery: a
// simple Query, an extended-protocol sequence ended by Sync, or an internal
// query. Batches are queued in the order they were sent; the upstream reader
// attributes every response to the head of the queue (or to the open batch,
// for extended messages not yet followed by Sync).
type batch struct {
	internal    bool // responses are consumed by the proxy, never shown to the client
	suppressRFQ bool // relay responses but hand the ReadyForQuery to the proxy
	done        chan *result

	// Client-visible extended-protocol bookkeeping (guarded by session.mu).
	msgs      int // messages forwarded in this batch
	nParse    int
	nBind     int
	nClose    int
	seenParse int
	seenBind  int
	seenClose int
	injParse  int // ordinal of an injected Parse whose ParseComplete is swallowed
	injBind   int
	injClose  int                     // CloseCompletes with an ordinal above this are injected (-1: none)
	refusal   *pgproto3.ErrorResponse // replaces the injected statement's error
	eager     bool                    // client sent Flush: flush every response
	flushed   bool                    // a client Flush sent this (still open) batch upstream
	viaSync   bool                    // closed by a client Sync (extended protocol)
	awaitSync bool                    // Postgres ignored the closing Sync (copy-in); the next client Sync ends it
	// parses are the client Parse messages of this batch, in order. An entry
	// is recorded as a prepared statement only when its ParseComplete
	// arrives; a Parse that Postgres rejects or skips never replaces the
	// proxy's record of what the name really runs upstream.
	parses     []*parseOp
	parsesSeen int
	fin        chan struct{} // closed when the batch's ReadyForQuery was processed

	// Reader-only.
	res *result
}

// parseOp is a client Parse waiting for its ParseComplete.
type parseOp struct {
	name     string
	ps       *preparedStmt
	gen      uint64 // session.simpleGen when sent (a simple Query drops the unnamed statement)
	resolved bool   // ParseComplete seen, or the batch failed before it
	dropped  bool   // Close/DEALLOCATE of the name sent after this Parse
}

// result collects an internal query's (or suppressed statement's) outcome.
type result struct {
	fields   []string
	rows     [][][]byte
	tags     []string
	err      *pgproto3.ErrorResponse
	txStatus byte
	lost     error
}

func (r *result) failed() bool { return r.err != nil || r.lost != nil }

func (r *result) errText() string {
	switch {
	case r.err != nil:
		return r.err.Message
	case r.lost != nil:
		return r.lost.Error()
	}
	return ""
}

type session struct {
	srv          *Server
	log          *slog.Logger
	agentID      string
	instanceID   string
	upstreamName string
	upCfg        config.UpstreamConfig
	// adminUser is the integration's admin user when the upstream is
	// integration-backed (the session runs as the agent's own role); "" for
	// a YAML ("legacy") upstream.
	adminUser string
	proxyPID  uint32
	proxyKey  []byte

	client net.Conn
	be     *pgproto3.Backend // reads client messages (session goroutine only)
	cmu    sync.Mutex        // guards cw/cbuf
	cw     *bufio.Writer
	cbuf   []byte

	up    net.Conn
	upPID uint32
	upKey []byte
	fe    *pgproto3.Frontend // reads upstream messages (reader goroutine only)
	uw    *bufio.Writer      // writes upstream (session goroutine only)
	ubuf  []byte

	mu         sync.Mutex
	queue      []*batch
	open       *batch
	txStatus   byte
	params     map[string]string
	pending    []pendingHandle          // snapshot handles awaiting the end of the client's transaction
	prepared   map[string]*preparedStmt // statements prepared through Fortik (extended protocol)
	simpleGen  uint64                   // simple Queries sent upstream (each drops the unnamed statement)
	copyIn     bool                     // upstream is in copy-in mode and the client has not ended it
	portal     *batch                   // batch that created the client's unnamed portal (nil: none can be live)
	busy       bool                     // the session goroutine is handling a client message
	cancelReq  bool                     // a CancelRequest arrived while nothing was running upstream
	reqCancel  context.CancelFunc       // aborts the current Decide call
	readerDone chan struct{}
	closeOnce  sync.Once
	closed     chan struct{}

	// Session goroutine only.
	discarding  bool                  // extended refusal: drop client messages until Sync
	directErr   bool                  // refusal error already sent; send RFQ at Sync
	tables      map[string]*tableInfo // catalog cache
	unnamedStmt bool                  // the client may hold an unnamed prepared statement upstream
	reqCtx      context.Context       // context for Decide while handling a client message
	serverMajor int
}

type pendingHandle struct {
	actionID       string
	snapshotSchema string
	snapshotTable  string
}

func newSession(srv *Server, client net.Conn, be *pgproto3.Backend, hj *pgconn.HijackedConn,
	agentID, instanceID, upName string, up config.UpstreamConfig, adminUser string, log *slog.Logger) *session {
	s := &session{
		srv: srv, log: log, agentID: agentID, instanceID: instanceID,
		upstreamName: upName, upCfg: up, adminUser: adminUser,
		client: client, be: be, cw: bufio.NewWriterSize(client, clientBufSize),
		up: hj.Conn, upPID: hj.PID, upKey: append([]byte(nil), hj.SecretKey...),
		fe: hj.Frontend, uw: bufio.NewWriterSize(hj.Conn, upstreamBufSize),
		open: newBatch(), txStatus: hj.TxStatus, params: map[string]string{},
		readerDone: make(chan struct{}), closed: make(chan struct{}),
		tables: map[string]*tableInfo{}, prepared: map[string]*preparedStmt{},
	}
	for k, v := range hj.ParameterStatuses {
		s.params[k] = v
	}
	if v := hj.ParameterStatuses["server_version"]; v != "" {
		f := strings.FieldsFunc(v, func(r rune) bool { return r < '0' || r > '9' })
		if len(f) > 0 {
			s.serverMajor, _ = strconv.Atoi(f[0])
		}
	}
	return s
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.client.Close()
		_ = s.up.Close()
	})
}

// run is the session goroutine: it reads client messages, decides and
// forwards them. A second goroutine relays upstream responses.
func (s *session) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.readLoop()
	go s.flushLoop()
	defer func() {
		s.close()
		<-s.readerDone
		s.failPending("session ended before the transaction committed")
	}()
	for {
		msg, err := s.be.Receive()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.log.Debug("client read ended", "err", err)
			}
			return
		}
		if err := s.handleClient(ctx, msg); err != nil {
			if !errors.Is(err, errSessionClosed) {
				s.log.Warn("session terminated", "err", err)
				s.sendClient(true, fatal("08006", "fortik: session terminated: "+err.Error()))
			}
			return
		}
	}
}

func newBatch() *batch { return &batch{injClose: -1, fin: make(chan struct{})} }

// reservedName reports whether a statement or portal name is reserved for
// the proxy's own extended-protocol messages.
func reservedName(n string) bool { return strings.HasPrefix(n, internalPrefix) }

const internalPrefix = "__fortik_"

// beginRequest marks the session busy with a client message that is
// classified and decided, so a CancelRequest arriving meanwhile is recorded
// (and aborts the Decide call) instead of being lost.
func (s *session) beginRequest(ctx context.Context) func() {
	rctx, rcancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.busy = true
	s.reqCancel = rcancel
	s.mu.Unlock()
	s.reqCtx = rctx
	return func() {
		rcancel()
		s.reqCtx = nil
		s.mu.Lock()
		s.busy = false
		s.reqCancel = nil
		if len(s.queue) == 0 && s.open.msgs == 0 {
			// Nothing is running or buffered: a cancel has nothing to act on.
			s.cancelReq = false
		}
		s.mu.Unlock()
	}
}

func (s *session) handleClient(ctx context.Context, msg pgproto3.FrontendMessage) error {
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Parse, *pgproto3.Bind:
		defer s.beginRequest(ctx)()
	}
	switch m := msg.(type) {
	case *pgproto3.Query:
		if s.discarding {
			return nil
		}
		return s.handleQuery(ctx, m.String)
	case *pgproto3.Parse:
		if s.discarding {
			return nil
		}
		if reservedName(m.Name) {
			return s.refuseExtended(refusalCode("42501", "fortik: refused: statement names starting with "+internalPrefix+" are reserved", ""))
		}
		return s.handleParse(ctx, m)
	case *pgproto3.Bind:
		if s.discarding {
			return nil
		}
		if reservedName(m.PreparedStatement) || reservedName(m.DestinationPortal) {
			return s.refuseExtended(refusalCode("42501", "fortik: refused: statement and portal names starting with "+internalPrefix+" are reserved", ""))
		}
		return s.handleBind(ctx, m)
	case *pgproto3.Close:
		if s.discarding {
			return nil
		}
		if m.ObjectType == 'S' {
			s.forgetStmt(m.Name, false)
		}
		return s.forwardExt(m, func(b *batch) { b.nClose++ })
	case *pgproto3.Describe, *pgproto3.Execute:
		if s.discarding {
			return nil
		}
		return s.forwardExt(m, nil)
	case *pgproto3.Flush:
		if s.discarding {
			return s.flushClient()
		}
		s.mu.Lock()
		s.open.eager = true
		s.mu.Unlock()
		if err := s.writeUp(m); err != nil {
			return err
		}
		if err := s.flushUp(); err != nil {
			return err
		}
		s.mu.Lock()
		s.open.flushed = s.open.msgs > 0
		s.mu.Unlock()
		return s.cancelIfRequested(ctx)
	case *pgproto3.Sync:
		return s.handleSync(ctx)
	case *pgproto3.CopyData, *pgproto3.CopyDone, *pgproto3.CopyFail:
		if s.discarding {
			return nil
		}
		if err := s.writeUp(m); err != nil {
			return err
		}
		if _, ok := m.(*pgproto3.CopyData); !ok {
			// The client ended copy-in: Postgres leaves copy mode.
			s.mu.Lock()
			s.copyIn = false
			s.mu.Unlock()
			return s.flushUp()
		}
		return nil
	case *pgproto3.FunctionCall:
		// Fastpath calls bypass SQL classification entirely: refuse.
		if s.discarding {
			return nil
		}
		return s.refuseSimple(refusalPlain("fortik: refused: fastpath function calls are not supported through Fortik"))
	case *pgproto3.Terminate:
		_ = s.writeUp(m)
		_ = s.flushUp()
		return errSessionClosed
	default:
		return fmt.Errorf("unexpected client message %T", msg)
	}
}

// forgetStmt drops the proxy's record of a prepared statement (Close,
// DEALLOCATE), including Parses of that name still awaiting ParseComplete.
// Forgetting is always safe: a Bind of an unknown name is refused.
func (s *session) forgetStmt(name string, all bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if all {
		s.prepared = map[string]*preparedStmt{}
	} else {
		delete(s.prepared, name)
	}
	for _, b := range append(append([]*batch{}, s.queue...), s.open) {
		for _, op := range b.parses {
			if all || op.name == name {
				op.dropped = true
			}
		}
	}
}

// ---- cancellation ----

// onCancelRequest handles a client CancelRequest. A statement running
// upstream is cancelled there. A statement the proxy is still deciding (or
// preparing with internal queries) is marked: it is refused with 57014
// instead of being forwarded, and internal snapshot steps are never
// cancelled.
func (s *session) onCancelRequest(ctx context.Context) error {
	s.mu.Lock()
	inflight := false
	if len(s.queue) > 0 {
		inflight = !s.queue[0].internal
	} else {
		inflight = s.open.msgs > 0 && s.open.flushed
	}
	if !inflight && (s.busy || len(s.queue) > 0 || s.open.msgs > 0) {
		s.cancelReq = true
		if s.reqCancel != nil {
			s.reqCancel()
		}
	}
	s.mu.Unlock()
	if inflight {
		return s.cancelUpstream(ctx)
	}
	return nil
}

// takeCancel consumes a pending cancel request.
func (s *session) takeCancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.cancelReq
	s.cancelReq = false
	return v
}

// cancelIfRequested forwards a pending cancel once the client's work is
// actually upstream (after a Sync/Flush sent it).
func (s *session) cancelIfRequested(ctx context.Context) error {
	if !s.takeCancel() {
		return nil
	}
	if err := s.cancelUpstream(ctx); err != nil {
		s.log.Warn("forwarding cancel request failed", "err", err)
	}
	return nil
}

func cancelErr() *pgproto3.ErrorResponse {
	return errResp("57014", "canceling statement due to user request", "", "")
}

// ---- upstream writes (session goroutine only) ----

func (s *session) writeUp(m pgproto3.FrontendMessage) error {
	buf, err := m.Encode(s.ubuf[:0])
	if err != nil {
		return err
	}
	s.ubuf = buf[:0]
	if _, err := s.uw.Write(buf); err != nil {
		return s.upErr(err)
	}
	return nil
}

func (s *session) flushUp() error {
	if err := s.uw.Flush(); err != nil {
		return s.upErr(err)
	}
	return nil
}

func (s *session) upErr(err error) error {
	select {
	case <-s.closed:
		return errSessionClosed
	default:
	}
	return fmt.Errorf("upstream write: %w", err)
}

// forwardExt forwards an extended-protocol message as part of the open batch.
func (s *session) forwardExt(m pgproto3.FrontendMessage, count func(*batch)) error {
	s.mu.Lock()
	s.open.msgs++
	if count != nil {
		count(s.open)
	}
	s.mu.Unlock()
	return s.writeUp(m)
}

// closeBatch queues the open batch (it ends with the Sync/Query about to be
// written) and starts a new one. Must be called BEFORE writing the message.
func (s *session) closeBatch(mod func(*batch)) *batch {
	s.mu.Lock()
	b := s.open
	if mod != nil {
		mod(b)
	}
	s.queue = append(s.queue, b)
	s.open = newBatch()
	s.mu.Unlock()
	return b
}

func (s *session) handleSync(ctx context.Context) error {
	if s.discarding {
		s.discarding = false
		if s.directErr {
			// Nothing was in flight when the refusal was sent and nothing has
			// been forwarded since: answer the Sync ourselves.
			s.directErr = false
			return s.sendClient(true, &pgproto3.ReadyForQuery{TxStatus: s.status()})
		}
	}
	// Postgres ignores Sync in copy-in mode; after an extended-protocol COPY
	// the batch already queued needs the next Sync for its ReadyForQuery.
	// Neither starts a new batch.
	s.mu.Lock()
	start := !s.copyIn
	if start {
		for _, b := range s.queue {
			if b.awaitSync {
				b.awaitSync = false
				start = false
				break
			}
		}
	}
	s.mu.Unlock()
	if start {
		s.closeBatch(func(b *batch) { b.viaSync = true })
	}
	if err := s.writeUp(&pgproto3.Sync{}); err != nil {
		return err
	}
	if err := s.flushUp(); err != nil {
		return err
	}
	return s.cancelIfRequested(ctx)
}

// forwardQuery forwards a simple Query unchanged. Postgres drops the unnamed
// statement and portal on every simple Query; the proxy's view follows.
func (s *session) forwardQuery(sql string, mod func(*batch)) (*batch, error) {
	b := s.closeBatch(mod)
	s.noteSimpleQuery()
	if err := s.writeUp(&pgproto3.Query{String: sql}); err != nil {
		return b, err
	}
	return b, s.flushUp()
}

func (s *session) noteSimpleQuery() {
	s.unnamedStmt = false
	s.mu.Lock()
	s.simpleGen++
	delete(s.prepared, "")
	s.portal = nil
	s.mu.Unlock()
}

// unnamedLive reports whether the client may still use an unnamed statement
// or portal upstream: internal queries must then avoid the simple protocol.
func (s *session) unnamedLive() bool {
	if s.unnamedStmt {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.portal != nil
}

// idle reports whether no client request is in flight upstream.
func (s *session) idle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) == 0 && s.open.msgs == 0
}

func (s *session) status() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txStatus
}

// internalQuery runs sql on the upstream session and consumes the response.
// Callers must ensure idle(). guard bounds the wait (0 = none); when it
// expires the session is terminated because its state is unknown.
func (s *session) internalQuery(sql string, guard time.Duration) (*result, error) {
	b := &batch{internal: true, done: make(chan *result, 1), res: &result{}, injClose: -1, fin: make(chan struct{})}
	s.mu.Lock()
	s.queue = append(s.queue, b)
	s.mu.Unlock()
	s.noteSimpleQuery()
	if err := s.writeUp(&pgproto3.Query{String: sql}); err != nil {
		return nil, err
	}
	if err := s.flushUp(); err != nil {
		return nil, err
	}
	return s.awaitInternal(b, guard)
}

// internalExt runs steps (one statement each) on the upstream session over
// the extended protocol, on proxy-owned statement and portal names, ending
// with one Sync. Unlike a simple Query it leaves the client's unnamed
// statement and portal alone. Steps after a failing one are skipped by
// Postgres. Leftovers of an earlier failed run are closed first (Close of a
// missing name is not an error).
func (s *session) internalExt(steps []string, guard time.Duration) (*result, error) {
	b := &batch{internal: true, done: make(chan *result, 1), res: &result{}, injClose: -1, fin: make(chan struct{})}
	s.mu.Lock()
	s.queue = append(s.queue, b)
	s.mu.Unlock()
	for i, q := range steps {
		name := fmt.Sprintf("%sint_%d", internalPrefix, i)
		for _, m := range []pgproto3.FrontendMessage{
			&pgproto3.Close{ObjectType: 'P', Name: name},
			&pgproto3.Close{ObjectType: 'S', Name: name},
			&pgproto3.Parse{Name: name, Query: q},
			&pgproto3.Bind{DestinationPortal: name, PreparedStatement: name},
			&pgproto3.Execute{Portal: name},
			&pgproto3.Close{ObjectType: 'P', Name: name},
			&pgproto3.Close{ObjectType: 'S', Name: name},
		} {
			if err := s.writeUp(m); err != nil {
				return nil, err
			}
		}
	}
	if err := s.writeUp(&pgproto3.Sync{}); err != nil {
		return nil, err
	}
	if err := s.flushUp(); err != nil {
		return nil, err
	}
	return s.awaitInternal(b, guard)
}

func (s *session) awaitInternal(b *batch, guard time.Duration) (*result, error) {
	var timer <-chan time.Time
	if guard > 0 {
		t := time.NewTimer(guard)
		defer t.Stop()
		timer = t.C
	}
	select {
	case r := <-b.done:
		return r, nil
	case <-s.readerDone:
		return nil, errSessionClosed
	case <-timer:
		// The upstream session state is now unknown: terminate (fail closed).
		s.log.Error("internal query did not complete in time; terminating session")
		s.close()
		return nil, errSessionClosed
	}
}

// ---- client writes (any goroutine) ----

func (s *session) sendClient(flush bool, msgs ...pgproto3.BackendMessage) error {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	for _, m := range msgs {
		buf, err := m.Encode(s.cbuf[:0])
		if err != nil {
			return err
		}
		s.cbuf = buf[:0]
		if _, err := s.cw.Write(buf); err != nil {
			return err
		}
	}
	if flush {
		return s.cw.Flush()
	}
	return nil
}

func (s *session) flushClient() error {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	return s.cw.Flush()
}

// flushLoop flushes buffered client output periodically, so slow result
// streams and responses the client waits on without Sync are never stuck.
func (s *session) flushLoop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.cmu.Lock()
			if s.cw.Buffered() > 0 {
				_ = s.cw.Flush()
			}
			s.cmu.Unlock()
		}
	}
}

// ---- upstream reader ----

func (s *session) readLoop() {
	defer close(s.readerDone)
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			select {
			case <-s.closed:
			default:
				s.log.Warn("upstream connection lost", "err", err)
				_ = s.sendClient(true, fatal("08006", "fortik: upstream connection lost"))
			}
			s.close()
			return
		}
		if err := s.dispatch(msg); err != nil {
			select {
			case <-s.closed:
			default:
				s.log.Warn("relay failed", "err", err)
			}
			s.close()
			return
		}
	}
}

func (s *session) current() *batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) > 0 {
		return s.queue[0]
	}
	return s.open
}

func (s *session) asyncFlush() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) == 0 && s.open.msgs == 0
}

func (s *session) dispatch(msg pgproto3.BackendMessage) error {
	b := s.current()
	switch m := msg.(type) {
	case *pgproto3.ParameterStatus:
		s.mu.Lock()
		s.params[m.Name] = m.Value
		s.mu.Unlock()
		return s.sendClient(s.asyncFlush(), m)
	case *pgproto3.NotificationResponse:
		return s.sendClient(s.asyncFlush(), m)
	case *pgproto3.NoticeResponse:
		if b.internal {
			return nil
		}
		return s.sendClient(s.asyncFlush(), m)
	case *pgproto3.ReadyForQuery:
		return s.onReady(b, m)
	}
	if b.internal {
		return collect(b.res, msg)
	}
	s.mu.Lock()
	flush := b.eager
	s.mu.Unlock()
	switch m := msg.(type) {
	case *pgproto3.ParseComplete:
		s.mu.Lock()
		b.seenParse++
		swallow := b.injParse > 0 && b.seenParse == b.injParse
		if !swallow && b.parsesSeen < len(b.parses) {
			// The client Parse this answers now really exists upstream.
			op := b.parses[b.parsesSeen]
			b.parsesSeen++
			op.resolved = true
			if !op.dropped && (op.name != "" || op.gen == s.simpleGen) {
				s.prepared[op.name] = op.ps
			}
		}
		s.mu.Unlock()
		if swallow {
			return nil
		}
	case *pgproto3.BindComplete:
		s.mu.Lock()
		b.seenBind++
		swallow := b.injBind > 0 && b.seenBind == b.injBind
		s.mu.Unlock()
		if swallow {
			return nil
		}
	case *pgproto3.CloseComplete:
		s.mu.Lock()
		b.seenClose++
		swallow := b.injClose >= 0 && b.seenClose > b.injClose
		s.mu.Unlock()
		if swallow {
			return nil
		}
	case *pgproto3.ErrorResponse:
		flush = true
		s.mu.Lock()
		ref := b.refusal
		s.failParses(b)
		s.copyIn = false // an error ends copy-in mode
		s.mu.Unlock()
		if ref != nil && m.Code == "42501" && m.Message == ref.Message {
			msg = ref
		}
		if b.suppressRFQ && b.res != nil && b.res.err == nil {
			c := *m
			b.res.err = &c
		}
	case *pgproto3.CommandComplete:
		if string(m.CommandTag) == "COMMIT" {
			// The client's transaction committed (COMMIT, END, COMMIT AND
			// CHAIN). Snapshots taken in it are verified before the client
			// sees the result: ROLLBACK TO SAVEPOINT may have discarded them.
			s.mu.Lock()
			hs := s.pending
			s.pending = nil
			s.mu.Unlock()
			if len(hs) > 0 {
				s.verifyCommitted(hs)
			}
		}
	case *pgproto3.CopyInResponse:
		flush = true
		s.mu.Lock()
		s.copyIn = true
		if b.viaSync && !b.awaitSync {
			// Postgres received (and ignored) the Sync that closed this
			// batch while in copy-in mode. Empty Sync-only batches queued
			// behind it were ignored the same way.
			b.awaitSync = true
			kept := s.queue[:0]
			for _, q := range s.queue {
				if q != b && !q.internal && q.viaSync && q.msgs == 0 && len(q.parses) == 0 {
					close(q.fin)
					continue
				}
				kept = append(kept, q)
			}
			s.queue = kept
		}
		s.mu.Unlock()
	case *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse:
		flush = true
	}
	return s.sendClient(flush, msg)
}

// failParses handles client Parses of b that got no ParseComplete (the batch
// failed): Postgres rejected or skipped them, so the names still run what
// they ran before. A recorded statement of that name is decided again at its
// next Bind; the unnamed statement may or may not have been dropped, so it
// is forgotten (a Bind of it is refused until the client parses again).
// Caller holds s.mu.
func (s *session) failParses(b *batch) {
	for _, op := range b.parses[b.parsesSeen:] {
		op.resolved = true
		if op.name == "" {
			delete(s.prepared, "")
		} else if old := s.prepared[op.name]; old != nil {
			old.fresh = false
		}
	}
	b.parsesSeen = len(b.parses)
}

func (s *session) onReady(b *batch, m *pgproto3.ReadyForQuery) error {
	s.mu.Lock()
	if len(s.queue) == 0 || s.queue[0] != b {
		s.mu.Unlock()
		return errors.New("protocol desync: ReadyForQuery without an outstanding request")
	}
	s.queue[0] = nil
	s.queue = s.queue[1:]
	s.txStatus = m.TxStatus
	s.failParses(b)
	s.copyIn = false
	close(b.fin)
	var rolledBack []pendingHandle
	if !b.internal && m.TxStatus == 'I' && len(s.pending) > 0 {
		// The transaction ended without a COMMIT tag: it rolled back.
		rolledBack = s.pending
		s.pending = nil
	}
	if m.TxStatus == 'I' && s.portal != nil && !s.batchPending(s.portal) {
		// Protocol portals do not outlive their transaction.
		s.portal = nil
	}
	if len(s.queue) == 0 && s.open.msgs == 0 && !s.busy {
		s.cancelReq = false
	}
	s.mu.Unlock()
	if len(rolledBack) > 0 {
		s.failHandles(rolledBack, "client transaction rolled back")
	}
	if b.internal || b.suppressRFQ {
		if b.res == nil {
			b.res = &result{}
		}
		b.res.txStatus = m.TxStatus
		b.done <- b.res
		return nil
	}
	return s.sendClient(true, m)
}

// batchPending reports whether b has not completed yet. Caller holds s.mu.
func (s *session) batchPending(b *batch) bool {
	if b == s.open {
		return true
	}
	for _, q := range s.queue {
		if q == b {
			return true
		}
	}
	return false
}

// collect records an internal query's response.
func collect(r *result, msg pgproto3.BackendMessage) error {
	switch m := msg.(type) {
	case *pgproto3.RowDescription:
		r.fields = r.fields[:0]
		for _, f := range m.Fields {
			r.fields = append(r.fields, string(f.Name))
		}
	case *pgproto3.DataRow:
		row := make([][]byte, len(m.Values))
		for i, v := range m.Values {
			if v != nil {
				row[i] = append([]byte{}, v...)
			}
		}
		r.rows = append(r.rows, row)
	case *pgproto3.CommandComplete:
		r.tags = append(r.tags, string(m.CommandTag))
	case *pgproto3.ErrorResponse:
		if r.err == nil {
			c := *m
			r.err = &c
		}
	case *pgproto3.CopyInResponse, *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse:
		return errors.New("internal query entered COPY mode")
	}
	return nil
}

// cancelUpstream sends a CancelRequest to the upstream backend.
func (s *session) cancelUpstream(ctx context.Context) error {
	addr := net.JoinHostPort(s.upCfg.Host, strconv.Itoa(s.upCfg.Port))
	if strings.HasPrefix(s.upCfg.Host, "/") {
		addr = fmt.Sprintf("%s/.s.PGSQL.%d", s.upCfg.Host, s.upCfg.Port)
	}
	network := "tcp"
	if strings.HasPrefix(s.upCfg.Host, "/") {
		network = "unix"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	buf, err := (&pgproto3.CancelRequest{ProcessID: s.upPID, SecretKey: s.upKey}).Encode(nil)
	if err != nil {
		return err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(buf); err != nil {
		return err
	}
	// The server closes the connection once the request is processed.
	var one [1]byte
	_, _ = c.Read(one[:])
	return nil
}
