// Package pgsql classifies PostgreSQL statements for Fortik and generates the
// SQL Fortik needs to prepare undo (row snapshots, rename-based safe forms).
//
// It is pure: no network access, no catalog knowledge. Everything here is
// derived from the libpg_query parse tree (the real PostgreSQL parser), so
// what Fortik classifies is exactly what the server will parse.
//
// Fail closed: Classify returns an error for anything it cannot parse; the
// caller must refuse the statement. Statements the classifier does not
// recognise are typed UNKNOWN (verb EXECUTE), which the policy refuses.
//
// Known limitation: unqualified relation names are reported in schema
// "public". The classifier cannot know the session's search_path.
package pgsql

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"

	"fortik/internal/action"
)

// StatementType values. The Rego policy depends on these exact strings.
const (
	TypeSelect            = "SELECT"
	TypeExplain           = "EXPLAIN"
	TypeInsert            = "INSERT"
	TypeUpdate            = "UPDATE"
	TypeMerge             = "MERGE"
	TypeDelete            = "DELETE"
	TypeSelectInto        = "SELECT_INTO"
	TypeDropTable         = "DROP_TABLE"
	TypeDropSchema        = "DROP_SCHEMA"
	TypeDropDatabase      = "DROP_DATABASE"
	TypeDropOther         = "DROP_OTHER"
	TypeTruncate          = "TRUNCATE"
	TypeAlterDropColumn   = "ALTER_DROP_COLUMN"
	TypeDDLCreate         = "DDL_CREATE"
	TypeDDLAlter          = "DDL_ALTER"
	TypeGrant             = "GRANT"
	TypeRole              = "ROLE"
	TypeSetRole           = "SET_ROLE"
	TypeCopyToStdout      = "COPY_TO_STDOUT"
	TypeCopyFromStdin     = "COPY_FROM_STDIN"
	TypeCopyProgram       = "COPY_PROGRAM"
	TypeCopyFile          = "COPY_FILE"
	TypeDangerousFunction = "DANGEROUS_FUNCTION"
	TypeExecuteBlock      = "EXECUTE_BLOCK"
	TypeMaintenance       = "MAINTENANCE"
	TypeLock              = "LOCK"
	TypeNotify            = "NOTIFY"
	TypeTransaction       = "TRANSACTION"
	TypeSession           = "SESSION"
	TypeUnknown           = "UNKNOWN"
)

// typeVerb is the verb each statement type maps to.
var typeVerb = map[string]action.Verb{
	TypeSelect: action.VerbRead, TypeExplain: action.VerbRead,
	TypeInsert: action.VerbWrite, TypeUpdate: action.VerbWrite, TypeMerge: action.VerbWrite,
	TypeDelete: action.VerbDelete, TypeSelectInto: action.VerbWrite,
	TypeDropTable: action.VerbDelete, TypeDropSchema: action.VerbDelete,
	TypeDropDatabase: action.VerbDelete, TypeDropOther: action.VerbDelete,
	TypeTruncate: action.VerbDelete, TypeAlterDropColumn: action.VerbDelete,
	TypeDDLCreate: action.VerbWrite, TypeDDLAlter: action.VerbWrite,
	TypeGrant: action.VerbGrant, TypeRole: action.VerbGrant, TypeSetRole: action.VerbGrant,
	TypeCopyToStdout: action.VerbExport, TypeCopyFromStdin: action.VerbWrite,
	TypeCopyProgram: action.VerbExecute, TypeCopyFile: action.VerbExecute,
	TypeDangerousFunction: action.VerbExecute, TypeExecuteBlock: action.VerbExecute,
	TypeMaintenance: action.VerbExecute, TypeLock: action.VerbWrite, TypeNotify: action.VerbWrite,
	TypeTransaction: action.VerbRead, TypeSession: action.VerbRead, TypeUnknown: action.VerbExecute,
}

// VerbFor returns the verb a statement type maps to (EXECUTE when unknown).
func VerbFor(statementType string) action.Verb {
	if v, ok := typeVerb[statementType]; ok {
		return v
	}
	return action.VerbExecute
}

// Severity orders verbs for "most dangerous verb wins":
// GRANT > EXECUTE > DELETE > EXPORT > SEND > WRITE > READ.
func Severity(v action.Verb) int {
	switch v {
	case action.VerbGrant:
		return 7
	case action.VerbExecute:
		return 6
	case action.VerbDelete:
		return 5
	case action.VerbExport:
		return 4
	case action.VerbSend:
		return 3
	case action.VerbWrite:
		return 2
	case action.VerbRead:
		return 1
	}
	return 6 // unknown verbs are treated like EXECUTE
}

// Statement is one classified SQL statement.
type Statement struct {
	Verb          action.Verb
	StatementType string
	// Tables lists every relation referenced, "schema.table", primary first.
	// Unqualified names default to schema "public" (search_path is unknown).
	Tables []string
	Schema string // primary relation
	Table  string
	// SchemaQualified is false when the primary relation was written without
	// a schema (Schema is then the assumed "public").
	SchemaQualified bool
	// HasWhere / WhereEqualityColumns / HasUsingOrFrom describe the
	// DELETE/UPDATE (or SELECT) node that determined the classification.
	HasWhere             bool
	WhereEqualityColumns []string
	HasUsingOrFrom       bool
	HasCTE               bool
	HasParams            bool // contains $n parameter references
	// VolatileWhere: the deciding DELETE/UPDATE/SELECT's WHERE may select
	// different rows on each evaluation (volatile or unknown functions,
	// TABLESAMPLE, LIMIT/OFFSET or SKIP LOCKED in a subquery). A snapshot
	// cannot be trusted to capture the affected rows then.
	VolatileWhere bool
	// OnConflictUpdate: an INSERT anywhere in the statement has
	// ON CONFLICT ... DO UPDATE.
	OnConflictUpdate bool
	// MergeHasDelete: a MERGE anywhere in the statement has a WHEN ... THEN
	// DELETE clause.
	MergeHasDelete bool
	// Database is the dropped database for DROP DATABASE.
	Database           string
	DangerousFunctions []string
	// Functions lists every function called (lower-cased, "schema.name"
	// when qualified other than pg_catalog), sorted, deduplicated.
	Functions []string
	// SQL is the raw text of this statement. It can contain PII: never log it.
	SQL         string
	Normalized  string // constants replaced by $n
	Fingerprint string
	// Node is the top-level statement node; DML is the node that determined
	// the classification when it is an INSERT/UPDATE/DELETE/MERGE (it may be
	// nested in a CTE), nil otherwise.
	Node *pg_query.Node
	DML  *pg_query.Node

	topLevelDML   bool // DML is Node itself (not nested, not under EXPLAIN)
	whereCurrent  bool // WHERE CURRENT OF cursor
	dropTargets   int  // number of objects in DROP TABLE / TRUNCATE
	isExplainOnly bool
	version       int32 // parse tree version, needed to deparse
}

// Trivial reports whether the statement needs no Decide call (transaction
// control and harmless session settings).
func (s *Statement) Trivial() bool {
	return s.StatementType == TypeTransaction || s.StatementType == TypeSession
}

// SnapshotPreparable reports whether SnapshotSQL can capture exactly the
// rows this statement affects: a single-table DELETE/UPDATE at top level,
// without USING/FROM, without CTE, not WHERE CURRENT OF, and without a
// volatile WHERE (the snapshot and the statement must select the same rows).
func (s *Statement) SnapshotPreparable() bool {
	if s.StatementType != TypeDelete && s.StatementType != TypeUpdate {
		return false
	}
	return s.topLevelDML && !s.HasUsingOrFrom && !s.HasCTE && !s.whereCurrent && !s.VolatileWhere && s.Table != ""
}

// SingleRelation reports whether a DROP TABLE / TRUNCATE targets exactly one table.
func (s *Statement) SingleRelation() bool { return s.dropTargets == 1 }

// ErrEmpty is never returned; an empty query yields zero statements.
var errParse = errors.New("pgsql: cannot parse SQL")

// Classify parses sql and classifies every statement in it. An error means
// the input could not be parsed; callers must fail closed.
func Classify(sql string) ([]Statement, error) {
	if !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 {
		return nil, fmt.Errorf("%w: statement text is not valid UTF-8", errParse)
	}
	tree, err := pg_query.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errParse, err)
	}
	out := make([]Statement, 0, len(tree.Stmts))
	for _, raw := range tree.Stmts {
		if raw == nil || raw.Stmt == nil {
			continue
		}
		text, err := stmtText(sql, raw)
		if err != nil {
			return nil, err
		}
		st, err := classifyRaw(raw.Stmt, text)
		if err != nil {
			return nil, err
		}
		st.version = tree.Version
		out = append(out, st)
	}
	return out, nil
}

// IsParseError reports whether err came from the parser.
func IsParseError(err error) bool { return errors.Is(err, errParse) }

func stmtText(sql string, raw *pg_query.RawStmt) (string, error) {
	start := int(raw.StmtLocation)
	if start < 0 || start > len(sql) {
		return "", fmt.Errorf("%w: bad statement location", errParse)
	}
	end := len(sql)
	if raw.StmtLen > 0 {
		end = start + int(raw.StmtLen)
		if end > len(sql) {
			return "", fmt.Errorf("%w: bad statement length", errParse)
		}
	}
	return strings.TrimSpace(sql[start:end]), nil
}

// finding is one candidate classification found in the tree.
type finding struct {
	typ  string
	node *pg_query.Node // DML node when the finding is a DML statement
}

func (f finding) verb() action.Verb { return VerbFor(f.typ) }

func classifyRaw(node *pg_query.Node, text string) (Statement, error) {
	st := Statement{Node: node, SQL: text}
	var err error
	if st.Normalized, err = pg_query.Normalize(text); err != nil {
		return st, fmt.Errorf("%w: normalize: %v", errParse, err)
	}
	// pg_query.Normalize leaves constants in some nodes (COMMENT ON, rule
	// and BEGIN ATOMIC bodies, COPY file names, ...): redact every literal
	// token that is left.
	if st.Normalized, err = redactLiterals(st.Normalized); err != nil {
		return st, fmt.Errorf("%w: normalize: %v", errParse, err)
	}
	if st.Fingerprint, err = pg_query.Fingerprint(text); err != nil {
		return st, fmt.Errorf("%w: fingerprint: %v", errParse, err)
	}

	// Top-level classification. EXPLAIN ANALYZE executes its statement, so it
	// takes the inner statement's classification.
	top := node
	explainOnly := false
	for {
		ex := top.GetExplainStmt()
		if ex == nil || ex.Query == nil {
			break
		}
		if !explainAnalyze(ex) {
			explainOnly = true
			break
		}
		top = ex.Query
	}
	var cur finding
	if explainOnly {
		cur = finding{typ: TypeExplain}
	} else {
		cur = classifyTop(top)
	}
	st.isExplainOnly = explainOnly

	// Walk the whole tree for nested dangers.
	var tables []string
	seenTables := map[string]bool{}
	addTable := func(t string) {
		if t != "" && !seenTables[t] {
			seenTables[t] = true
			tables = append(tables, t)
		}
	}
	var dangerous, funcs []string
	seenDanger, seenFunc := map[string]bool{}, map[string]bool{}
	walk(node.ProtoReflect(), func(m protoreflect.Message) {
		switch n := m.Interface().(type) {
		case *pg_query.WithClause:
			st.HasCTE = true
		case *pg_query.ParamRef:
			st.HasParams = true
		case *pg_query.CurrentOfExpr:
			st.whereCurrent = true
		case *pg_query.FuncCall:
			if fn := funcName(n); fn != "" && !seenFunc[fn] {
				seenFunc[fn] = true
				funcs = append(funcs, fn)
			}
			name, typ := dangerousCall(n)
			if typ == "" {
				return
			}
			if !seenDanger[name] {
				seenDanger[name] = true
				dangerous = append(dangerous, name)
			}
			if Severity(VerbFor(typ)) > Severity(cur.verb()) {
				cur = finding{typ: typ}
			}
		}
	})
	// Statements that run now. Rule actions and BEGIN ATOMIC bodies are only
	// stored by the DDL; they must not replace its classification.
	walkNow(node, func(n *pg_query.Node) {
		if ins := n.GetInsertStmt(); ins != nil && ins.OnConflictClause != nil &&
			ins.OnConflictClause.Action == pg_query.OnConflictAction_ONCONFLICT_UPDATE {
			st.OnConflictUpdate = true
		}
		if mg := n.GetMergeStmt(); mg != nil {
			for _, w := range mg.MergeWhenClauses {
				if wc := w.GetMergeWhenClause(); wc != nil && wc.CommandType == pg_query.CmdType_CMD_DELETE {
					st.MergeHasDelete = true
				}
			}
		}
	})
	if !explainOnly {
		// Nested data-modifying statements (CTEs, EXPLAIN ANALYZE, ...).
		walkNow(node, func(n *pg_query.Node) {
			if n == top {
				return
			}
			var f finding
			switch {
			case n.GetDeleteStmt() != nil:
				f = finding{typ: TypeDelete, node: n}
			case n.GetUpdateStmt() != nil:
				f = finding{typ: TypeUpdate, node: n}
			case n.GetInsertStmt() != nil:
				f = finding{typ: TypeInsert, node: n}
			case n.GetMergeStmt() != nil:
				f = finding{typ: TypeMerge, node: n}
			case n.GetSelectStmt() != nil && n.GetSelectStmt().IntoClause != nil:
				f = finding{typ: TypeSelectInto}
			default:
				return
			}
			if Severity(f.verb()) > Severity(cur.verb()) {
				cur = f
			}
		})
	}
	st.StatementType = cur.typ
	st.Verb = cur.verb()
	sort.Strings(dangerous)
	st.DangerousFunctions = dangerous
	sort.Strings(funcs)
	st.Functions = funcs
	if st.Functions == nil {
		st.Functions = []string{}
	}

	// Primary relation and WHERE facts come from the deciding node.
	primaryNode := cur.node
	if primaryNode == nil {
		primaryNode = top
	}
	if isDML(primaryNode) {
		st.DML = primaryNode
		st.topLevelDML = primaryNode == node
	}
	primary := primaryRelations(primaryNode)
	if len(primary) > 0 {
		st.Schema, st.Table = splitTable(primary[0])
		st.SchemaQualified = firstQualified(primaryNode)
	}
	switch cur.typ {
	case TypeDropTable, TypeTruncate:
		st.dropTargets = len(primary)
	}
	if d := top.GetDropdbStmt(); d != nil {
		st.Database = d.Dbname
	}
	for _, t := range primary {
		addTable(t)
	}
	firstRangeVarQualified, sawRangeVar := false, false
	walkRelations(node.ProtoReflect(), nil, func(rv *pg_query.RangeVar) {
		if !sawRangeVar {
			sawRangeVar, firstRangeVarQualified = true, rv.Schemaname != ""
		}
		addTable(rangeVarName(rv))
	})
	// Tables only referenced in a stored function body are not the
	// function's target.
	if st.Table == "" && len(tables) > 0 && top.GetCreateFunctionStmt() == nil {
		st.Schema, st.Table = splitTable(tables[0])
		st.SchemaQualified = firstRangeVarQualified
	}
	if st.Table == "*" { // schema-level target ("schema.*")
		st.Table = ""
	}
	st.Tables = tables
	if st.Tables == nil {
		st.Tables = []string{}
	}
	if st.DangerousFunctions == nil {
		st.DangerousFunctions = []string{}
	}

	var where *pg_query.Node
	switch {
	case primaryNode.GetDeleteStmt() != nil:
		d := primaryNode.GetDeleteStmt()
		where = d.WhereClause
		st.HasUsingOrFrom = len(d.UsingClause) > 0
	case primaryNode.GetUpdateStmt() != nil:
		u := primaryNode.GetUpdateStmt()
		where = u.WhereClause
		st.HasUsingOrFrom = len(u.FromClause) > 0
	case primaryNode.GetSelectStmt() != nil:
		where = primaryNode.GetSelectStmt().WhereClause
	}
	st.HasWhere = where != nil
	st.WhereEqualityColumns = equalityColumns(where)
	st.VolatileWhere = volatile(where)
	return st, nil
}

// volatile reports whether a WHERE clause may select different rows each
// time it is evaluated within one snapshot: a function not known to be
// IMMUTABLE/STABLE (random(), nextval(), clock_timestamp(), user-defined
// functions of unknown volatility), TABLESAMPLE, LIMIT/OFFSET in a subquery
// (row order is not guaranteed), or SKIP LOCKED. Operators are assumed
// stable (a user-defined volatile operator is not detected).
func volatile(where *pg_query.Node) bool {
	if where == nil {
		return false
	}
	found := false
	walk(where.ProtoReflect(), func(m protoreflect.Message) {
		switch x := m.Interface().(type) {
		case *pg_query.FuncCall:
			if !stableBuiltins[funcName(x)] {
				found = true
			}
		case *pg_query.RangeTableSample:
			found = true
		case *pg_query.SelectStmt:
			if x.LimitCount != nil || x.LimitOffset != nil {
				found = true
			}
		case *pg_query.LockingClause:
			if x.WaitPolicy == pg_query.LockWaitPolicy_LockWaitSkip {
				found = true
			}
		}
	})
	return found
}

// redactLiterals replaces every literal token left in sql (string, bit,
// hex, numeric constants, including dollar-quoted strings) with a $n
// placeholder numbered after the highest existing parameter.
func redactLiterals(sql string) (string, error) {
	res, err := pg_query.Scan(sql)
	if err != nil {
		return "", err
	}
	next := 0
	for _, tk := range res.Tokens {
		if tk.Token == pg_query.Token_PARAM && int(tk.End) <= len(sql) && tk.Start >= 0 {
			if n, err := strconv.Atoi(strings.TrimPrefix(sql[tk.Start:tk.End], "$")); err == nil && n > next {
				next = n
			}
		}
	}
	var b strings.Builder
	last := 0
	for _, tk := range res.Tokens {
		switch tk.Token {
		case pg_query.Token_SCONST, pg_query.Token_USCONST, pg_query.Token_BCONST,
			pg_query.Token_XCONST, pg_query.Token_ICONST, pg_query.Token_FCONST:
		default:
			continue
		}
		start, end := int(tk.Start), int(tk.End)
		if start < last || end > len(sql) || start > end {
			return "", errors.New("bad token offsets")
		}
		next++
		b.WriteString(sql[last:start])
		b.WriteString("$" + strconv.Itoa(next))
		last = end
	}
	b.WriteString(sql[last:])
	return b.String(), nil
}

// walkNow visits every *pg_query.Node that executes as part of the
// statement: it does not descend into rule actions (CREATE RULE) or SQL
// function bodies (BEGIN ATOMIC), which are only stored.
func walkNow(root *pg_query.Node, visit func(*pg_query.Node)) {
	walkPrune(root.ProtoReflect(), func(m protoreflect.Message) bool {
		switch m.Interface().(type) {
		case *pg_query.RuleStmt, *pg_query.CreateFunctionStmt:
			return false
		}
		if n, ok := m.Interface().(*pg_query.Node); ok {
			visit(n)
		}
		return true
	})
}

// walkRelations calls visit for every RangeVar that names a real relation,
// resolving unqualified names against the CTE names visible at that point:
// in a WITH list each CTE body sees the earlier siblings (all of them, and
// itself, when RECURSIVE); the statement body sees all of them. The target
// of INSERT/UPDATE/DELETE/MERGE and an INTO clause always name real
// relations.
func walkRelations(m protoreflect.Message, scope []map[string]bool, visit func(*pg_query.RangeVar)) {
	switch x := m.Interface().(type) {
	case *pg_query.RangeVar:
		if x.Schemaname == "" {
			for _, s := range scope {
				if s[x.Relname] {
					return
				}
			}
		}
		visit(x)
		return
	case *pg_query.IntoClause:
		scope = nil
	}
	withScope := func(extra map[string]bool) []map[string]bool {
		out := make([]map[string]bool, 0, len(scope)+1)
		return append(append(out, scope...), extra)
	}
	fields := m.Descriptor().Fields()
	inner := scope
	withFd := fields.ByName("with_clause")
	if withFd != nil && m.Has(withFd) {
		wc, _ := m.Get(withFd).Message().Interface().(*pg_query.WithClause)
		if wc != nil {
			all := map[string]bool{}
			for _, c := range wc.Ctes {
				if cte := c.GetCommonTableExpr(); cte != nil {
					all[cte.Ctename] = true
				}
			}
			earlier := map[string]bool{}
			for _, c := range wc.Ctes {
				cte := c.GetCommonTableExpr()
				if cte == nil {
					walkRelations(c.ProtoReflect(), scope, visit)
					continue
				}
				visible := map[string]bool{}
				src := earlier
				if wc.Recursive {
					src = all
				}
				for k := range src {
					visible[k] = true
				}
				walkRelations(cte.ProtoReflect(), withScope(visible), visit)
				earlier[cte.Ctename] = true
			}
			inner = withScope(all)
		}
	} else {
		withFd = nil
	}
	isDML := false
	switch m.Interface().(type) {
	case *pg_query.InsertStmt, *pg_query.UpdateStmt, *pg_query.DeleteStmt, *pg_query.MergeStmt:
		isDML = true
	}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
			continue
		}
		if fd.IsMap() || !m.Has(fd) || (withFd != nil && fd.Number() == withFd.Number()) {
			continue
		}
		s := inner
		if isDML && fd.Name() == "relation" {
			s = nil
		}
		v := m.Get(fd)
		if fd.IsList() {
			l := v.List()
			for j := 0; j < l.Len(); j++ {
				walkRelations(l.Get(j).Message(), s, visit)
			}
			continue
		}
		walkRelations(v.Message(), s, visit)
	}
}

func isDML(n *pg_query.Node) bool {
	return n != nil && (n.GetDeleteStmt() != nil || n.GetUpdateStmt() != nil ||
		n.GetInsertStmt() != nil || n.GetMergeStmt() != nil)
}

func explainAnalyze(ex *pg_query.ExplainStmt) bool {
	for _, o := range ex.Options {
		d := o.GetDefElem()
		if d == nil || !strings.EqualFold(d.Defname, "analyze") {
			continue
		}
		return defElemBool(d, true)
	}
	return false
}

// defElemBool interprets an option value; absent means def.
func defElemBool(d *pg_query.DefElem, def bool) bool {
	if d.Arg == nil {
		return def
	}
	if b := d.Arg.GetBoolean(); b != nil {
		return b.Boolval
	}
	if c := d.Arg.GetAConst(); c != nil {
		switch {
		case c.GetBoolval() != nil:
			return c.GetBoolval().Boolval
		case c.GetIval() != nil:
			return c.GetIval().Ival != 0
		case c.GetSval() != nil:
			return parseBoolString(c.GetSval().Sval, def)
		}
	}
	if s := d.Arg.GetString_(); s != nil {
		return parseBoolString(s.Sval, def)
	}
	if i := d.Arg.GetInteger(); i != nil {
		return i.Ival != 0
	}
	return true // unknown representation: assume it executes (fail closed)
}

func parseBoolString(s string, def bool) bool {
	switch strings.ToLower(s) {
	case "false", "off", "0", "no", "f", "n":
		return false
	case "true", "on", "1", "yes", "t", "y":
		return true
	}
	return true
}

// walk visits every message in the tree in field-number order.
func walk(m protoreflect.Message, visit func(protoreflect.Message)) {
	walkPrune(m, func(m protoreflect.Message) bool { visit(m); return true })
}

// walkPrune is walk where visit returning false skips the message's children.
func walkPrune(m protoreflect.Message, visit func(protoreflect.Message) bool) {
	if !visit(m) {
		return
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
			continue
		}
		if fd.IsMap() || !m.Has(fd) {
			continue
		}
		v := m.Get(fd)
		if fd.IsList() {
			l := v.List()
			for j := 0; j < l.Len(); j++ {
				walkPrune(l.Get(j).Message(), visit)
			}
			continue
		}
		walkPrune(v.Message(), visit)
	}
}

func rangeVarName(rv *pg_query.RangeVar) string {
	schema := rv.Schemaname
	if schema == "" {
		if rv.Relpersistence == "t" {
			schema = "pg_temp"
		} else {
			schema = "public"
		}
	}
	return schema + "." + rv.Relname
}

func splitTable(t string) (string, string) {
	i := strings.IndexByte(t, '.')
	if i < 0 {
		return "public", t
	}
	return t[:i], t[i+1:]
}

// nameList converts a list of String nodes (qualified name) to schema.table.
func nameList(n *pg_query.Node) string {
	l := n.GetList()
	if l == nil {
		if s := n.GetString_(); s != nil {
			return "public." + s.Sval
		}
		return ""
	}
	var parts []string
	for _, it := range l.Items {
		if s := it.GetString_(); s != nil {
			parts = append(parts, s.Sval)
		}
	}
	switch len(parts) {
	case 1:
		return "public." + parts[0]
	case 2:
		return parts[0] + "." + parts[1]
	case 3: // db.schema.table
		return parts[1] + "." + parts[2]
	}
	return ""
}

// primaryRelations returns the relations a statement node acts on directly.
func primaryRelations(n *pg_query.Node) []string {
	if n == nil {
		return nil
	}
	rv := func(r *pg_query.RangeVar) []string {
		if r == nil {
			return nil
		}
		return []string{rangeVarName(r)}
	}
	switch {
	case n.GetDeleteStmt() != nil:
		return rv(n.GetDeleteStmt().Relation)
	case n.GetUpdateStmt() != nil:
		return rv(n.GetUpdateStmt().Relation)
	case n.GetInsertStmt() != nil:
		return rv(n.GetInsertStmt().Relation)
	case n.GetMergeStmt() != nil:
		return rv(n.GetMergeStmt().Relation)
	case n.GetTruncateStmt() != nil:
		var out []string
		for _, r := range n.GetTruncateStmt().Relations {
			if x := r.GetRangeVar(); x != nil {
				out = append(out, rangeVarName(x))
			}
		}
		return out
	case n.GetDropStmt() != nil:
		d := n.GetDropStmt()
		switch d.RemoveType {
		case pg_query.ObjectType_OBJECT_TABLE, pg_query.ObjectType_OBJECT_VIEW,
			pg_query.ObjectType_OBJECT_MATVIEW, pg_query.ObjectType_OBJECT_FOREIGN_TABLE,
			pg_query.ObjectType_OBJECT_INDEX, pg_query.ObjectType_OBJECT_SEQUENCE:
			var out []string
			for _, o := range d.Objects {
				if t := nameList(o); t != "" {
					out = append(out, t)
				}
			}
			return out
		}
		if d.RemoveType == pg_query.ObjectType_OBJECT_SCHEMA {
			// Dropping a schema drops every table in it: "schema.*".
			var out []string
			for _, o := range d.Objects {
				if s := o.GetString_(); s != nil {
					out = append(out, s.Sval+".*")
				}
			}
			return out
		}
	case n.GetGrantStmt() != nil:
		g := n.GetGrantStmt()
		if g.Targtype == pg_query.GrantTargetType_ACL_TARGET_ALL_IN_SCHEMA {
			var out []string
			for _, o := range g.Objects {
				if s := o.GetString_(); s != nil {
					out = append(out, s.Sval+".*")
				}
			}
			return out
		}
	case n.GetRuleStmt() != nil:
		return rv(n.GetRuleStmt().Relation)
	case n.GetCreateTrigStmt() != nil:
		return rv(n.GetCreateTrigStmt().Relation)
	case n.GetAlterTableStmt() != nil:
		return rv(n.GetAlterTableStmt().Relation)
	case n.GetCopyStmt() != nil:
		return rv(n.GetCopyStmt().Relation)
	case n.GetCreateStmt() != nil:
		return rv(n.GetCreateStmt().Relation)
	case n.GetCreateTableAsStmt() != nil:
		if in := n.GetCreateTableAsStmt().Into; in != nil {
			return rv(in.Rel)
		}
	case n.GetSelectStmt() != nil && n.GetSelectStmt().IntoClause != nil:
		return rv(n.GetSelectStmt().IntoClause.Rel)
	case n.GetIndexStmt() != nil:
		return rv(n.GetIndexStmt().Relation)
	case n.GetRenameStmt() != nil:
		return rv(n.GetRenameStmt().Relation)
	case n.GetLockStmt() != nil:
		var out []string
		for _, r := range n.GetLockStmt().Relations {
			if x := r.GetRangeVar(); x != nil {
				out = append(out, rangeVarName(x))
			}
		}
		return out
	}
	return nil
}

func funcName(fc *pg_query.FuncCall) string {
	var parts []string
	for _, n := range fc.Funcname {
		if s := n.GetString_(); s != nil {
			parts = append(parts, strings.ToLower(s.Sval))
		}
	}
	if len(parts) == 2 && parts[0] == "pg_catalog" {
		parts = parts[1:]
	}
	return strings.Join(parts, ".")
}

// firstQualified reports whether the first primary relation was written
// with an explicit schema.
func firstQualified(n *pg_query.Node) bool {
	if c := n.GetCreateTableAsStmt(); c != nil && c.Into != nil && c.Into.Rel != nil {
		return c.Into.Rel.Schemaname != ""
	}
	var found, q bool
	walk(n.ProtoReflect(), func(m protoreflect.Message) {
		if found {
			return
		}
		switch x := m.Interface().(type) {
		case *pg_query.RangeVar:
			found, q = true, x.Schemaname != ""
		case *pg_query.List:
			if d := n.GetDropStmt(); d != nil {
				found, q = true, len(x.Items) > 1
			}
		}
	})
	return q
}

// equalityColumns returns columns compared with "=" to a constant or $n in
// the top-level AND conjuncts of a WHERE clause.
func equalityColumns(where *pg_query.Node) []string {
	if where == nil {
		return []string{}
	}
	var conj []*pg_query.Node
	var flatten func(n *pg_query.Node)
	flatten = func(n *pg_query.Node) {
		if b := n.GetBoolExpr(); b != nil && b.Boolop == pg_query.BoolExprType_AND_EXPR {
			for _, a := range b.Args {
				flatten(a)
			}
			return
		}
		conj = append(conj, n)
	}
	flatten(where)
	seen := map[string]bool{}
	out := []string{}
	for _, c := range conj {
		e := c.GetAExpr()
		if e == nil || e.Kind != pg_query.A_Expr_Kind_AEXPR_OP || len(e.Name) != 1 {
			continue
		}
		if s := e.Name[0].GetString_(); s == nil || s.Sval != "=" {
			continue
		}
		col := columnName(e.Lexpr)
		if col == "" || !isConstOrParam(e.Rexpr) {
			col = columnName(e.Rexpr)
			if col == "" || !isConstOrParam(e.Lexpr) {
				continue
			}
		}
		if !seen[col] {
			seen[col] = true
			out = append(out, col)
		}
	}
	return out
}

// columnName returns the column of a bare column reference. A cast or any
// other expression around the column is not an equality on the column
// itself (id::int = 5 matches every numeric id that rounds to 5).
func columnName(n *pg_query.Node) string {
	if n == nil {
		return ""
	}
	cr := n.GetColumnRef()
	if cr == nil || len(cr.Fields) == 0 {
		return ""
	}
	if s := cr.Fields[len(cr.Fields)-1].GetString_(); s != nil {
		return s.Sval
	}
	return ""
}

func isConstOrParam(n *pg_query.Node) bool {
	if n == nil {
		return false
	}
	if tc := n.GetTypeCast(); tc != nil {
		return isConstOrParam(tc.Arg)
	}
	if c := n.GetAConst(); c != nil {
		return !c.Isnull
	}
	return n.GetParamRef() != nil
}
