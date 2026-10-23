package pgproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"fortik/internal/action"
	"fortik/internal/decide"
	"fortik/internal/pgsql"
	"fortik/internal/policy"
	"fortik/internal/undo"
)

const (
	protoSimple   = "simple"
	protoExtended = "extended"
	reducedSnap   = "snapshot_rows"
)

// plan is one statement's classification, Action and decision.
type plan struct {
	st             *pgsql.Statement
	act            action.Action
	undoPreparable bool
	info           *tableInfo // nil when not looked up
	safeSQL        string
	out            decide.Outcome
}

// ---- simple protocol ----

func (s *session) handleQuery(ctx context.Context, sql string) error {
	stmts, err := pgsql.Classify(sql)
	if err != nil {
		s.log.Info("statement refused: unparseable SQL", "protocol", protoSimple)
		s.log.Debug("parse error", "err", err)
		return s.refuseSimple(refusalCode("42601",
			"fortik: refused: SQL could not be parsed or classified (fail closed): "+trimParseErr(err), ""))
	}
	if len(stmts) == 0 || allTrivial(stmts) {
		if s.takeCancel() {
			return s.refuseSimple(cancelErr())
		}
		_, err := s.forwardQuery(sql, nil)
		s.noteForwarded(stmts)
		return err
	}
	canPre := s.idle() && s.status() != 'E'
	plans := make([]*plan, 0, len(stmts))
	for i := range stmts {
		st := &stmts[i]
		if st.Trivial() {
			continue
		}
		p := s.buildPlan(ctx, st, protoSimple, len(stmts), canPre)
		if refusal := s.decidePlan(ctx, p); refusal != nil {
			return s.refuseSimple(refusal)
		}
		plans = append(plans, p)
	}
	// Every statement must be allowed (or a single allow_reduced) before
	// anything runs.
	var reduced *plan
	for _, p := range plans {
		switch p.out.Result.Decision {
		case policy.Allow:
		case policy.AllowReduced:
			reduced = p
		default:
			return s.refuseSimple(refusalFor(p))
		}
	}
	if reduced == nil {
		if s.takeCancel() {
			return s.refuseSimple(cancelErr())
		}
		_, err := s.forwardQuery(sql, nil)
		s.noteForwarded(stmts)
		return err
	}
	if len(stmts) != 1 {
		return s.refuseSimple(refusalReduced(reduced, "the reduced form requires a single statement per query (multi-statement query string)"))
	}
	if reason := checkReducedForm(reduced.out.Result.ReducedForm); reason != "" {
		return s.refuseSimple(refusalReduced(reduced, reason))
	}
	if !reduced.undoPreparable {
		return s.refuseSimple(refusalReduced(reduced, "undo cannot be prepared for this statement (undo_preparable=false)"))
	}
	return s.runWithSnapshot(ctx, sql, reduced)
}

// checkReducedForm returns "" when the proxy can honour rf (Phase 1: only
// {"snapshot_rows": true}).
func checkReducedForm(rf map[string]any) string {
	if len(rf) == 0 {
		return "allow_reduced without a reduced form the proxy can apply"
	}
	var unknown []string
	for k := range rf {
		if k != reducedSnap {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return "reduced form key(s) not supported by the Postgres proxy: " + strings.Join(unknown, ", ")
	}
	if v, ok := rf[reducedSnap].(bool); !ok || !v {
		return "reduced form snapshot_rows must be true"
	}
	return ""
}

// ---- extended protocol ----

func (s *session) handleParse(ctx context.Context, m *pgproto3.Parse) error {
	stmts, err := pgsql.Classify(m.Query)
	if err != nil {
		s.log.Info("statement refused: unparseable SQL", "protocol", protoExtended)
		s.log.Debug("parse error", "err", err)
		return s.refuseExtended(refusalCode("42601",
			"fortik: refused: SQL could not be parsed or classified (fail closed): "+trimParseErr(err), ""))
	}
	if len(stmts) > 1 {
		return s.refuseExtended(refusalCode("42601", "fortik: refused: multiple statements in one extended-protocol Parse", ""))
	}
	ps := &preparedStmt{trivial: true, fresh: true}
	if len(stmts) == 1 {
		ps.st = stmts[0]
		ps.trivial = stmts[0].Trivial()
	}
	if !ps.trivial {
		if refusal := s.decideExtended(ctx, &ps.st); refusal != nil {
			return s.refuseExtended(refusal)
		}
	}
	if s.takeCancel() {
		return s.refuseExtended(cancelErr())
	}
	s.noteForwarded(stmts)
	// The decision covers the first execution; later Binds of a cached
	// prepared statement are decided again (see handleBind). The statement
	// is recorded only when Postgres confirms the Parse (ParseComplete).
	op := &parseOp{name: m.Name, ps: ps}
	if m.Name == "" {
		s.unnamedStmt = true
	}
	return s.forwardExt(m, func(b *batch) {
		b.nParse++
		op.gen = s.simpleGen
		b.parses = append(b.parses, op)
	})
}

// preparedStmt is a statement the proxy let through Parse and Postgres
// created. fresh is guarded by session.mu.
type preparedStmt struct {
	st      pgsql.Statement
	trivial bool
	fresh   bool // the Parse decision has not been used by a Bind yet
}

// decideExtended decides one extended-protocol statement and returns a
// refusal unless it may run unchanged.
func (s *session) decideExtended(ctx context.Context, st *pgsql.Statement) *pgproto3.ErrorResponse {
	canPre := s.idle() && s.status() != 'E'
	p := s.buildPlan(ctx, st, protoExtended, 1, canPre)
	if refusal := s.decidePlan(ctx, p); refusal != nil {
		return refusal
	}
	switch p.out.Result.Decision {
	case policy.Allow:
		return nil
	case policy.AllowReduced:
		return refusalReduced(p, "reduced forms (row snapshots) are not supported over the extended query protocol in Phase 1; use the simple query protocol")
	}
	return refusalFor(p)
}

// handleBind forwards a Bind. Executing a statement prepared in an earlier
// Parse again is a new action: it is decided again before it runs.
func (s *session) handleBind(ctx context.Context, m *pgproto3.Bind) error {
	ps, err := s.lookupForBind(m.PreparedStatement)
	if err != nil {
		return err
	}
	if ps == nil {
		return s.refuseExtended(refusalCode("26000",
			fmt.Sprintf("fortik: refused: prepared statement %q was not prepared through Fortik on this connection", m.PreparedStatement), ""))
	}
	s.mu.Lock()
	fresh := ps.fresh
	ps.fresh = false
	s.mu.Unlock()
	if !ps.trivial && !fresh {
		if refusal := s.decideExtended(ctx, &ps.st); refusal != nil {
			return s.refuseExtended(refusal)
		}
	}
	if s.takeCancel() {
		return s.refuseExtended(cancelErr())
	}
	return s.forwardExt(m, func(b *batch) {
		b.nBind++
		if m.DestinationPortal == "" {
			s.portal = b
		}
	})
}

// lookupForBind returns what name will run upstream when the Bind arrives
// there: a Parse of that name earlier in the same batch (if that Parse fails,
// Postgres skips the Bind too), else the confirmed record. When a Parse of
// that name in an earlier, still unanswered batch is pending, it waits for
// that batch to learn whether Postgres accepted it.
func (s *session) lookupForBind(name string) (*preparedStmt, error) {
	for {
		s.mu.Lock()
		for i := len(s.open.parses) - 1; i >= 0; i-- {
			if op := s.open.parses[i]; op.name == name && !op.dropped {
				s.mu.Unlock()
				return op.ps, nil
			}
		}
		var wait chan struct{}
		for i := len(s.queue) - 1; i >= 0 && wait == nil; i-- {
			for _, op := range s.queue[i].parses {
				if op.name == name && !op.resolved && !op.dropped {
					wait = s.queue[i].fin
					break
				}
			}
		}
		if wait == nil {
			ps := s.prepared[name]
			s.mu.Unlock()
			return ps, nil
		}
		s.mu.Unlock()
		select {
		case <-wait:
		case <-s.readerDone:
			return nil, errSessionClosed
		}
	}
}

// ---- action building and decision ----

func allTrivial(stmts []pgsql.Statement) bool {
	for i := range stmts {
		if !stmts[i].Trivial() {
			return false
		}
	}
	return true
}

func (s *session) buildPlan(ctx context.Context, st *pgsql.Statement, protocol string, count int, canPre bool) *plan {
	p := &plan{st: st}
	actID := action.NewID("act")
	labels := s.srv.dataLabels(st.Tables)

	// Catalog facts (primary key / unique indexes) for narrowness and undo.
	needInfo := st.Table != "" && ((st.HasWhere && len(st.WhereEqualityColumns) > 0) ||
		(st.StatementType == pgsql.TypeUpdate && st.SnapshotPreparable()))
	if needInfo && canPre {
		info, err := s.tableInfo(st)
		if err != nil {
			s.log.Debug("catalog lookup failed", "err", err)
		} else {
			p.info = info
		}
	}
	narrow := p.info != nil && p.info.narrow(st.WhereEqualityColumns)
	switch st.StatementType {
	case pgsql.TypeDelete:
		p.undoPreparable = st.SnapshotPreparable()
	case pgsql.TypeUpdate:
		p.undoPreparable = st.SnapshotPreparable() && p.info != nil && len(p.info.pk) > 0
	}

	var rowsEst *int64
	// Estimated rows (plain EXPLAIN, never executed): for wide writes (undo
	// snapshots) and for reads of tables carrying data labels (bulk reads of
	// sensitive data, POL-113).
	estimate := (st.StatementType == pgsql.TypeDelete || st.StatementType == pgsql.TypeUpdate) && !narrow
	if st.StatementType == pgsql.TypeSelect && len(labels) > 0 {
		estimate = true
	}
	if estimate && canPre && explainSafe(st) {
		if n, err := s.estimateRows(st, narrow); err == nil {
			rowsEst = &n
		} else {
			// No estimate: a sensitive read then fails closed (POL-114).
			s.log.Debug("rows estimate unavailable", "err", err)
		}
	}

	target := map[string]any{
		"upstream":            s.upstreamName,
		"database":            s.upCfg.Database,
		"environment":         s.upCfg.Environment,
		"statement_type":      st.StatementType,
		"tables":              append([]string{}, st.Tables...),
		"schema":              st.Schema,
		"table":               st.Table,
		"has_where":           st.HasWhere,
		"where_narrow":        narrow,
		"undo_preparable":     p.undoPreparable,
		"dangerous_functions": append([]string{}, st.DangerousFunctions...),
		"protocol":            protocol,
		"statement_count":     count,
		"fingerprint":         st.Fingerprint,
		"normalized_sql":      st.Normalized,
		"on_conflict_update":  st.OnConflictUpdate,
		"merge_has_delete":    st.MergeHasDelete,
		"volatile_where":      st.VolatileWhere,
	}
	if (st.StatementType == pgsql.TypeDropTable || st.StatementType == pgsql.TypeTruncate) && st.SingleRelation() {
		if sql, trash, err := pgsql.SafeRenameSQL(st, s.srv.now()); err == nil {
			p.safeSQL = sql
			target["safe_form"] = map[string]any{"kind": undo.KindPGRename, "sql": sql, "trash_table": trash}
		}
	}
	p.act = action.Action{
		ActionID:   actID,
		AgentID:    s.agentID,
		InstanceID: s.instanceID,
		System:     action.SystemPostgres,
		Verb:       st.Verb,
		Target:     target,
		PayloadSummary: action.PayloadSummary{
			DataLabels:   labels,
			RowsEstimate: rowsEst,
		},
		Reversible: st.Verb == action.VerbRead,
		TS:         s.srv.now().UTC(),
		Source:     action.SourcePGProxy,
	}
	return p
}

// estimateRows returns the planner's row estimate for st, or an error when
// none can be had safely. It never plans a statement over a view or another
// non-table relation (planning could run user code before Fortik decided).
// A parameterised SELECT is planned generically, with default selectivities
// that a predicate such as "id > $1" or "BETWEEN $1 AND $2" makes as small as
// the caller likes, so unless it is a unique-key lookup on one table its
// estimate is bounded below by the size of the largest table it reads.
func (s *session) estimateRows(st *pgsql.Statement, narrow bool) (int64, error) {
	facts, err := s.relationFacts(st.Tables)
	if err != nil {
		return 0, err
	}
	if !facts.plain {
		return 0, errors.New("statement references a view or other non-table relation: not planned before the decision")
	}
	n, err := s.explainRows(st)
	if err != nil {
		return 0, err
	}
	if st.StatementType == pgsql.TypeSelect && st.HasParams && !(narrow && len(st.Tables) == 1) {
		if !facts.analysed {
			return 0, errors.New("parameterised read of a table with no planner row count (never analysed)")
		}
		if facts.maxTuples > n {
			n = facts.maxTuples
		}
	}
	return n, nil
}

// explainOnlyBuiltins are built-ins that are not STABLE (so they make a WHERE
// volatile) but that the planner never evaluates: VOLATILE functions are not
// constant-folded, so planning a statement that calls them runs nothing.
var explainOnlyBuiltins = map[string]bool{
	"random": true, "clock_timestamp": true, "timeofday": true, "gen_random_uuid": true,
	// built-in aggregates and row serialisers (never folded: their arguments
	// are rows, not constants)
	"json_agg": true, "jsonb_agg": true, "json_object_agg": true, "jsonb_object_agg": true,
	"row_to_json": true, "xmlagg": true, "stddev": true, "variance": true,
}

// explainSafe reports whether planning st (plain EXPLAIN) runs no user code.
// Planning can constant-fold IMMUTABLE functions, so a user-defined function
// could run before Fortik decided: statements calling anything but known
// built-ins get no rows_estimate.
func explainSafe(st *pgsql.Statement) bool {
	for _, f := range st.Functions {
		if !pgsql.StableBuiltin(f) && !explainOnlyBuiltins[f] {
			return false
		}
	}
	return true
}

// decidePlan calls Decide; it returns a refusal when no usable decision exists.
func (s *session) decidePlan(ctx context.Context, p *plan) *pgproto3.ErrorResponse {
	start := time.Now()
	dctx := ctx
	if s.reqCtx != nil {
		dctx = s.reqCtx // cancelled by a client CancelRequest
	}
	out, err := s.srv.d.Decide(dctx, p.act)
	if s.takeCancel() {
		s.log.Info("statement cancelled by the client while being decided", "action_id", p.act.ActionID,
			"statement_type", p.st.StatementType, "fingerprint", p.st.Fingerprint)
		return cancelErr()
	}
	if err != nil {
		s.log.Warn("decide failed; statement refused", "action_id", p.act.ActionID,
			"statement_type", p.st.StatementType, "fingerprint", p.st.Fingerprint, "err", err)
		return refusalCode("42501", "fortik: refused: no decision could be made (fail closed): "+err.Error(),
			"action_id="+p.act.ActionID)
	}
	if out.Action.ActionID != "" && out.Action.ActionID != p.act.ActionID {
		// The decider is expected to keep our pre-assigned id (snapshot names use it).
		s.log.Warn("decider changed the action id", "sent", p.act.ActionID, "got", out.Action.ActionID)
		p.act.ActionID = out.Action.ActionID
	}
	p.out = out
	s.log.Info("statement decided",
		"action_id", p.act.ActionID, "statement_type", p.st.StatementType, "verb", string(p.st.Verb),
		"fingerprint", p.st.Fingerprint, "protocol", p.act.Target["protocol"],
		"decision", string(out.Result.Decision), "class", string(out.Result.Class),
		"rule_id", out.Result.RuleID, "fail_closed", out.FailClosed, "decide_us", time.Since(start).Microseconds())
	return nil
}

// noteForwarded invalidates the catalog cache when a statement that can
// change relations or name resolution is forwarded.
func (s *session) noteForwarded(stmts []pgsql.Statement) {
	for i := range stmts {
		n := stmts[i].Node
		if d := n.GetDeallocateStmt(); d != nil {
			s.forgetStmt(d.Name, d.Name == "" || d.Isall)
		}
		if d := n.GetDiscardStmt(); d != nil && d.Target == pg_query.DiscardMode_DISCARD_ALL {
			s.forgetStmt("", true)
		}
	}
	for i := range stmts {
		switch stmts[i].StatementType {
		case pgsql.TypeSelect, pgsql.TypeExplain, pgsql.TypeInsert, pgsql.TypeUpdate, pgsql.TypeDelete,
			pgsql.TypeMerge, pgsql.TypeTransaction, pgsql.TypeCopyToStdout, pgsql.TypeCopyFromStdin,
			pgsql.TypeLock, pgsql.TypeNotify:
			continue
		}
		s.tables = map[string]*tableInfo{}
		return
	}
}

func (srv *Server) dataLabels(tables []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tables {
		schema, table, _ := strings.Cut(t, ".")
		for _, r := range srv.cfg.DataLabels {
			if !labelMatch(r.Match, schema, table) {
				continue
			}
			for _, l := range r.Labels {
				if !seen[l] {
					seen[l] = true
					out = append(out, l)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// labelMatch matches a rule ("schema.table", "schema.*", "*.table", "*")
// against a relation. A schema-level target ("schema.*", e.g. DROP SCHEMA)
// covers every table of the schema, so any table part of the rule matches.
func labelMatch(rule, schema, table string) bool {
	rs, rt, ok := strings.Cut(rule, ".")
	if !ok {
		return rule == "*"
	}
	return (rs == "*" || strings.EqualFold(rs, schema)) && (rt == "*" || table == "*" || strings.EqualFold(rt, table))
}

// ---- refusals ----

func errResp(code, msg, detail, hint string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: code,
		Message: msg, Detail: detail, Hint: hint}
}

func refusalPlain(msg string) *pgproto3.ErrorResponse { return errResp("42501", msg, "", "") }

func refusalCode(code, msg, detail string) *pgproto3.ErrorResponse {
	return errResp(code, msg, detail, "")
}

func approverHint(p *plan) string {
	if p.safeSQL != "" {
		return "A security approver can approve the safe form: " + p.safeSQL
	}
	return "Ask an approver to review this action in Fortik"
}

func refusalFor(p *plan) *pgproto3.ErrorResponse {
	r := p.out.Result
	d := string(r.Decision)
	if r.Decision != policy.Hold {
		d = string(policy.Deny)
	}
	reason := r.Reason
	if r.Decision != policy.Hold && r.Decision != policy.Deny {
		reason = fmt.Sprintf("unrecognised decision %q (fail closed): %s", r.Decision, r.Reason)
	}
	return errResp("42501", fmt.Sprintf("fortik: %s (%s) by %s: %s", d, r.Class, r.RuleID, reason),
		"action_id="+p.act.ActionID, approverHint(p))
}

func refusalReduced(p *plan, why string) *pgproto3.ErrorResponse {
	r := p.out.Result
	return errResp("42501", fmt.Sprintf("fortik: deny (%s) by %s: allowed only in a reduced form the proxy cannot honour: %s", r.Class, r.RuleID, why),
		"action_id="+p.act.ActionID, approverHint(p))
}

func trimParseErr(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "pgsql: cannot parse SQL: ")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// raiseSQL builds a DO block that raises e inside Postgres, so a refusal in
// a transaction block aborts the upstream transaction exactly as if
// Postgres itself had raised the error.
func raiseSQL(e *pgproto3.ErrorResponse) string {
	body := fmt.Sprintf("BEGIN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = %s, DETAIL = %s, HINT = %s; END",
		pgsql.QuoteLiteral(e.Message), pgsql.QuoteLiteral(e.Detail), pgsql.QuoteLiteral(e.Hint))
	for {
		var b [8]byte
		_, _ = rand.Read(b[:])
		tag := "$fortik_" + hex.EncodeToString(b[:]) + "$"
		if !strings.Contains(body, tag) {
			return "DO " + tag + body + tag
		}
	}
}

// refuseSimple answers a refused simple Query (or fastpath call).
func (s *session) refuseSimple(e *pgproto3.ErrorResponse) error {
	if s.idle() {
		if st := s.status(); st != 'T' {
			return s.sendClient(true, e, &pgproto3.ReadyForQuery{TxStatus: st})
		}
	}
	// Inside a transaction block (or behind pipelined requests): make
	// Postgres raise the refusal so the transaction is aborted and the error
	// is delivered in order. The reader swaps in our exact ErrorResponse.
	_, err := s.forwardQuery(raiseSQL(e), func(b *batch) { b.refusal = e })
	return err
}

// refuseExtended refuses at Parse/Bind: error now, discard until Sync, and
// abort the upstream transaction / pipelined implicit transaction if needed.
func (s *session) refuseExtended(e *pgproto3.ErrorResponse) error {
	s.discarding = true
	s.mu.Lock()
	idle := len(s.queue) == 0 && s.open.msgs == 0
	st := s.txStatus
	s.mu.Unlock()
	if idle && st != 'T' {
		s.directErr = true
		return s.sendClient(true, e)
	}
	// Make Postgres raise the refusal in order, on a proxy-owned statement
	// and portal (the client's unnamed statement and portal are untouched).
	// The leading Closes remove leftovers of an earlier refusal. Every
	// injected response except the error is swallowed by the reader.
	const name = internalPrefix + "refuse"
	s.mu.Lock()
	s.open.msgs += 5
	s.open.refusal = e
	s.open.injClose = s.open.nClose
	s.open.nParse++
	s.open.injParse = s.open.nParse
	s.open.nBind++
	s.open.injBind = s.open.nBind
	s.mu.Unlock()
	for _, m := range []pgproto3.FrontendMessage{
		&pgproto3.Close{ObjectType: 'P', Name: name},
		&pgproto3.Close{ObjectType: 'S', Name: name},
		&pgproto3.Parse{Name: name, Query: raiseSQL(e)},
		&pgproto3.Bind{DestinationPortal: name, PreparedStatement: name},
		&pgproto3.Execute{Portal: name},
		&pgproto3.Flush{},
	} {
		if err := s.writeUp(m); err != nil {
			return err
		}
	}
	return s.flushUp()
}

// ---- snapshot (allow_reduced: snapshot_rows) ----

func (s *session) runWithSnapshot(ctx context.Context, sql string, p *plan) error {
	st := p.st
	status := s.status()
	if status == 'E' || !s.idle() {
		return s.refuseSimple(refusalReduced(p, "a row snapshot cannot be taken now (transaction failed or requests in flight)"))
	}
	info := p.info
	if info == nil {
		var err error
		if info, err = s.tableInfo(st); err != nil {
			info = nil
		}
	}
	if info == nil || !info.exists {
		return s.refuseSimple(refusalReduced(p, "the target table could not be resolved for the snapshot"))
	}
	snapTable := pgsql.SnapshotTableName(st.Table, p.act.ActionID)
	snapSQL, err := pgsql.SnapshotSQL(st, pgsql.SnapshotSchema, snapTable)
	if err != nil {
		return s.refuseSimple(refusalReduced(p, "snapshot SQL could not be generated"))
	}
	data, _ := json.Marshal(undo.PGRowsData{
		Upstream: s.upstreamName, Database: s.upCfg.Database,
		Schema: info.schema, Table: st.Table,
		SnapshotSchema: pgsql.SnapshotSchema, SnapshotTable: snapTable,
		Op: st.StatementType, PKColumns: info.pk, Statement: st.Fingerprint,
	})
	now := s.srv.now().UTC()
	h := undo.Handle{
		ActionID: p.act.ActionID, AgentID: s.agentID, Kind: undo.KindPGRows, Data: data,
		Status: undo.StatusPrepared, ExpiresAt: now.Add(s.srv.undoCfg.SnapshotRetention), CreatedAt: now,
	}
	if err := s.srv.us.Prepare(ctx, h, actor); err != nil {
		s.log.Error("undo prepare failed; statement refused", "action_id", h.ActionID, "err", err)
		return s.refuseSimple(refusalReduced(p, "the undo handle could not be recorded"))
	}
	log := s.log.With("action_id", h.ActionID, "statement_type", st.StatementType, "fingerprint", st.Fingerprint)
	fail := func(reason string) {
		if err := s.srv.us.Fail(context.WithoutCancel(ctx), h.ActionID, reason); err != nil {
			log.Error("undo fail transition failed", "err", err)
		}
	}
	snapErr := func(r *result) *pgproto3.ErrorResponse {
		code := "58000"
		if r != nil && r.err != nil && r.err.Code != "" {
			code = r.err.Code
		}
		msg := "fortik: undo snapshot failed; statement not executed"
		if r != nil && r.failed() {
			msg += ": " + r.errText()
		}
		return errResp(code, msg, "action_id="+h.ActionID, "")
	}

	if status == 'T' {
		// Inside the client's transaction: snapshot in the same transaction,
		// then forward normally; the handle activates when the client commits.
		for _, q := range s.snapshotSteps(snapSQL, snapTable) {
			r, err := s.internalQuery(q, 0)
			if err != nil {
				fail("snapshot failed: " + err.Error())
				return err
			}
			if r.failed() {
				fail("snapshot failed: " + r.errText())
				log.Warn("snapshot failed inside client transaction; statement not executed")
				// The upstream transaction is now aborted, like any error.
				return s.sendClient(true, snapErr(r), &pgproto3.ReadyForQuery{TxStatus: r.txStatus})
			}
		}
		if s.takeCancel() {
			// The statement never runs; aborting the transaction (as a
			// cancel would) also discards the snapshot.
			fail("statement cancelled by the client")
			return s.refuseSimple(cancelErr())
		}
		s.mu.Lock()
		s.pending = append(s.pending, pendingHandle{actionID: h.ActionID,
			snapshotSchema: pgsql.SnapshotSchema, snapshotTable: snapTable})
		s.mu.Unlock()
		_, err := s.forwardQuery(sql, nil)
		log.Info("statement forwarded with row snapshot (inside client transaction)")
		return err
	}

	// Idle: our own transaction around snapshot + statement.
	steps := append([]string{"BEGIN ISOLATION LEVEL REPEATABLE READ"}, s.snapshotSteps(snapSQL, snapTable)...)
	for _, q := range steps {
		r, err := s.internalQuery(q, 0)
		if err != nil {
			fail("snapshot failed: " + err.Error())
			return err
		}
		if r.failed() {
			fail("snapshot failed: " + r.errText())
			log.Warn("snapshot failed; statement not executed")
			rb, err := s.internalQuery("ROLLBACK", 0)
			if err != nil {
				return err
			}
			return s.sendClient(true, snapErr(r), &pgproto3.ReadyForQuery{TxStatus: rb.txStatus})
		}
	}
	if s.takeCancel() {
		fail("statement cancelled by the client")
		rb, err := s.internalQuery("ROLLBACK", 0)
		if err != nil {
			return err
		}
		log.Info("statement with row snapshot cancelled before it ran; rolled back")
		return s.sendClient(true, cancelErr(), &pgproto3.ReadyForQuery{TxStatus: rb.txStatus})
	}
	b, err := s.forwardQuery(sql, func(b *batch) {
		b.suppressRFQ = true
		b.done = make(chan *result, 1)
		b.res = &result{}
	})
	if err != nil {
		fail("statement could not be sent: " + err.Error())
		return err
	}
	var r *result
	select {
	case r = <-b.done:
	case <-s.readerDone:
		fail("upstream connection lost during the statement")
		return errSessionClosed
	}
	if r.txStatus != 'T' || r.err != nil {
		reason := "statement failed"
		if r.err != nil {
			reason += ": " + r.err.Message
		}
		rb, err := s.internalQuery("ROLLBACK", 0)
		fail(reason)
		log.Info("statement with row snapshot failed; rolled back")
		if err != nil {
			return err
		}
		return s.sendClient(true, &pgproto3.ReadyForQuery{TxStatus: rb.txStatus})
	}
	c, err := s.internalQuery("COMMIT", 0)
	if err != nil {
		fail("commit failed: " + err.Error())
		return err
	}
	if c.failed() || (len(c.tags) > 0 && c.tags[len(c.tags)-1] != "COMMIT") {
		fail("commit failed: " + c.errText())
		e := errResp("40000", "fortik: commit of statement and undo snapshot failed: "+c.errText(), "action_id="+h.ActionID, "")
		if c.err != nil {
			e.Code = c.err.Code
		}
		return s.sendClient(true, e, &pgproto3.ReadyForQuery{TxStatus: c.txStatus})
	}
	if err := s.srv.us.Activate(context.WithoutCancel(ctx), h.ActionID); err != nil {
		// The statement committed and the snapshot exists; only the store
		// transition failed. Report loudly; the handle stays prepared.
		log.Error("undo activate failed after commit", "err", err)
	} else {
		log.Info("statement committed with row snapshot", "snapshot_table", snapTable)
	}
	return s.sendClient(true, &pgproto3.ReadyForQuery{TxStatus: c.txStatus})
}

// snapshotSteps returns the statements that create the row snapshot.
//
// YAML ("legacy") upstream: CREATE SCHEMA IF NOT EXISTS fortik_undo, then the
// snapshot table, as the static upstream user.
//
// Integration-backed upstream: the session runs as the agent's own role, which
// has no CREATE on the database, so the schema must already exist (the
// integration tester checks it and write_role's CREATE on it). The snapshot
// table is created and owned by the agent's role, and SELECT on it is granted
// to the integration's admin user, who runs snapshot verification and undo.
func (s *session) snapshotSteps(snapSQL, snapTable string) []string {
	if s.adminUser == "" {
		return []string{"CREATE SCHEMA IF NOT EXISTS " + pgsql.QuoteIdent(pgsql.SnapshotSchema), snapSQL}
	}
	return []string{snapSQL,
		"GRANT SELECT ON TABLE " + pgsql.QuoteQualified(pgsql.SnapshotSchema, snapTable) + " TO " + pgsql.QuoteIdent(s.adminUser)}
}

// verifyConnConfig returns the login used for checks on a separate upstream
// connection: the integration's admin user (resolved afresh) for an
// integration-backed upstream, else the YAML upstream's static user.
func (s *session) verifyConnConfig(ctx context.Context, runtime map[string]string) (*pgconn.Config, error) {
	if s.adminUser == "" {
		return ConnConfig(ctx, s.upCfg, s.srv.sec, runtime)
	}
	if s.srv.roles == nil {
		return nil, errors.New("integration-backed session without a role broker")
	}
	cfg, u, err := s.srv.roles.AdminConnConfig(ctx, s.upstreamName, runtime)
	if err != nil {
		return nil, err
	}
	if u.Host != s.upCfg.Host || u.Port != s.upCfg.Port || u.Database != s.upCfg.Database {
		// The integration was re-pointed while this session was open.
		return nil, fmt.Errorf("integration postgres:%s now points at a different database", s.upstreamName)
	}
	return cfg, nil
}

// verifyCommitted resolves in-transaction snapshot handles after the
// client's transaction committed (called from the reader before the COMMIT
// result is relayed). The snapshot table is looked up on a separate
// connection: ROLLBACK TO SAVEPOINT (or a ROLLBACK earlier in the same query
// string) can have discarded it even though the transaction committed. A
// handle is activated only when its snapshot provably exists.
func (s *session) verifyCommitted(hs []pendingHandle) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	exists, err := s.snapshotsExist(ctx, hs)
	for _, h := range hs {
		var terr error
		switch {
		case err != nil:
			s.log.Error("could not verify undo snapshot after commit", "action_id", h.actionID, "err", err)
			terr = s.srv.us.Fail(ctx, h.actionID, "could not verify the snapshot after commit")
		case exists[h.actionID]:
			terr = s.srv.us.Activate(ctx, h.actionID)
		default:
			s.log.Warn("undo snapshot missing after commit (rolled back to a savepoint?)", "action_id", h.actionID)
			terr = s.srv.us.Fail(ctx, h.actionID, "snapshot discarded before the transaction committed")
		}
		if terr != nil {
			s.log.Error("undo handle transition failed", "action_id", h.actionID, "err", terr)
		}
	}
}

func (s *session) snapshotsExist(ctx context.Context, hs []pendingHandle) (map[string]bool, error) {
	cfg, err := s.verifyConnConfig(ctx, map[string]string{"application_name": "fortik:pgproxy:verify"})
	if err != nil {
		return nil, err
	}
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	out := map[string]bool{}
	for _, h := range hs {
		r := conn.ExecParams(ctx, "SELECT pg_catalog.to_regclass($1) IS NOT NULL",
			[][]byte{[]byte(pgsql.QuoteQualified(h.snapshotSchema, h.snapshotTable))}, nil, nil, nil).Read()
		if r.Err != nil {
			return nil, r.Err
		}
		if len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
			return nil, errors.New("unexpected result shape")
		}
		out[h.actionID] = string(r.Rows[0][0]) == "t"
	}
	return out, nil
}

func (s *session) failHandles(hs []pendingHandle, reason string) {
	for _, h := range hs {
		if err := s.srv.us.Fail(context.Background(), h.actionID, reason); err != nil {
			s.log.Error("undo handle transition failed", "action_id", h.actionID, "err", err)
		}
	}
}

func (s *session) failPending(reason string) {
	s.mu.Lock()
	hs := s.pending
	s.pending = nil
	s.mu.Unlock()
	s.failHandles(hs, reason)
}
