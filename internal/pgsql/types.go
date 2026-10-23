package pgsql

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// dangerousFuncs execute side effects outside normal data access (signal
// backends, read/write server files, open remote connections, run dynamic
// SQL, manipulate replication/WAL).
var dangerousFuncs = map[string]bool{
	"pg_terminate_backend": true, "pg_cancel_backend": true,
	"pg_reload_conf": true, "pg_rotate_logfile": true,
	"pg_read_file": true, "pg_read_binary_file": true, "pg_stat_file": true,
	"pg_ls_dir": true, "pg_ls_logdir": true, "pg_ls_waldir": true, "pg_ls_tmpdir": true,
	"pg_ls_archive_statusdir": true, "pg_ls_logicalsnapdir": true, "pg_ls_logicalmapdir": true,
	"pg_ls_replslotdir": true,
	"pg_file_write":     true, "pg_file_rename": true, "pg_file_unlink": true, "pg_file_sync": true,
	"lo_import": true, "lo_export": true, "lo_unlink": true,
	"pg_logical_emit_message": true, "pg_switch_wal": true, "pg_promote": true,
	"pg_create_restore_point": true, "pg_drop_replication_slot": true,
	"pg_create_physical_replication_slot": true, "pg_create_logical_replication_slot": true,
	"pg_backup_start": true, "pg_backup_stop": true,
	"pg_wal_replay_pause": true, "pg_wal_replay_resume": true,
	// Built-ins that run SQL passed as a string: the classifier cannot see
	// what that string does (audit of pg_catalog functions taking query text:
	// query_to_xml*, ts_stat, ts_rewrite(tsquery, text); cursor_to_xml reads
	// a cursor opened by an earlier, separately decided statement).
	"query_to_xml": true, "query_to_xmlschema": true, "query_to_xml_and_xmlschema": true,
	"cursor_to_xml": true, "cursor_to_xmlschema": true,
	"ts_stat": true,
	// These dump every table of a schema / of the database while naming
	// none, so table-based data labels would never apply.
	"schema_to_xml": true, "schema_to_xml_and_xmlschema": true,
	"database_to_xml": true, "database_to_xml_and_xmlschema": true,
}

// roleGUCs change the effective identity or bypass triggers/replication rules.
var roleGUCs = map[string]bool{
	"role": true, "session_authorization": true, "session_replication_role": true,
}

// sessionGUCs may be SET/RESET without a decision. client_encoding is
// deliberately absent: the proxy pins it to UTF8 upstream because the
// classifier parses UTF-8, and SET/RESET client_encoding or SET NAMES is
// typed UNKNOWN (refused).
var sessionGUCs = map[string]bool{
	"search_path": true, "timezone": true, "datestyle": true, "intervalstyle": true,
	"client_min_messages": true, "extra_float_digits": true,
	"statement_timeout": true, "lock_timeout": true, "idle_in_transaction_session_timeout": true,
	"application_name": true, "bytea_output": true, "standard_conforming_strings": true,
	"default_transaction_isolation": true, "transaction_isolation": true,
	"transaction": true, "session characteristics": true,
}

// dangerousCall returns the function name and the statement type it forces,
// or "" when the call is harmless.
func dangerousCall(fc *pg_query.FuncCall) (string, string) {
	if len(fc.Funcname) == 0 {
		return "", ""
	}
	s := fc.Funcname[len(fc.Funcname)-1].GetString_()
	if s == nil {
		return "", ""
	}
	name := strings.ToLower(s.Sval)
	switch {
	case dangerousFuncs[name], strings.HasPrefix(name, "dblink"):
		return name, TypeDangerousFunction
	case name == "ts_rewrite" && len(fc.Args) != 3:
		// ts_rewrite(tsquery, text) executes the text as a query; only the
		// 3-argument form (all tsquery) is harmless.
		return name, TypeDangerousFunction
	case name == "set_config":
		if len(fc.Args) == 0 {
			return name, TypeDangerousFunction
		}
		v, ok := constString(fc.Args[0])
		if !ok {
			return name, TypeDangerousFunction
		}
		g := strings.ToLower(strings.TrimSpace(v))
		if roleGUCs[g] {
			return name, TypeSetRole
		}
		if g == "client_encoding" {
			// The proxy classifies UTF-8; a different client encoding makes
			// Postgres lex the bytes differently (classifier bypass).
			return name, TypeDangerousFunction
		}
	}
	return "", ""
}

func constString(n *pg_query.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if tc := n.GetTypeCast(); tc != nil {
		return constString(tc.Arg)
	}
	if c := n.GetAConst(); c != nil && !c.Isnull && c.GetSval() != nil {
		return c.GetSval().Sval, true
	}
	return "", false
}

// classifyTop maps a top-level statement node to its statement type.
func classifyTop(n *pg_query.Node) finding {
	f := func(t string) finding { return finding{typ: t} }
	switch x := n.Node.(type) {
	case *pg_query.Node_SelectStmt:
		if x.SelectStmt.IntoClause != nil {
			return f(TypeSelectInto)
		}
		return f(TypeSelect)
	case *pg_query.Node_InsertStmt:
		return finding{typ: TypeInsert, node: n}
	case *pg_query.Node_UpdateStmt:
		return finding{typ: TypeUpdate, node: n}
	case *pg_query.Node_DeleteStmt:
		return finding{typ: TypeDelete, node: n}
	case *pg_query.Node_MergeStmt:
		return finding{typ: TypeMerge, node: n}
	case *pg_query.Node_CreateTableAsStmt:
		if x.CreateTableAsStmt.Query.GetExecuteStmt() != nil {
			// CREATE TABLE AS EXECUTE runs a prepared statement whose content
			// is not visible here; treat it like plain EXECUTE.
			return f(TypeUnknown)
		}
		if x.CreateTableAsStmt.Objtype == pg_query.ObjectType_OBJECT_MATVIEW {
			return f(TypeDDLCreate)
		}
		return f(TypeSelectInto)
	case *pg_query.Node_DeclareCursorStmt:
		if x.DeclareCursorStmt.Query != nil {
			return classifyTop(x.DeclareCursorStmt.Query)
		}
		return f(TypeUnknown)
	case *pg_query.Node_FetchStmt:
		return f(TypeSelect) // reads from a cursor that was itself decided at DECLARE
	case *pg_query.Node_ClosePortalStmt:
		return f(TypeSession)

	case *pg_query.Node_DropStmt:
		switch x.DropStmt.RemoveType {
		case pg_query.ObjectType_OBJECT_TABLE:
			return f(TypeDropTable)
		case pg_query.ObjectType_OBJECT_SCHEMA:
			return f(TypeDropSchema)
		}
		return f(TypeDropOther)
	case *pg_query.Node_DropdbStmt:
		return f(TypeDropDatabase)
	case *pg_query.Node_DropTableSpaceStmt, *pg_query.Node_DropUserMappingStmt,
		*pg_query.Node_DropSubscriptionStmt:
		return f(TypeDropOther)
	case *pg_query.Node_TruncateStmt:
		return f(TypeTruncate)

	case *pg_query.Node_AlterTableStmt:
		t := TypeDDLAlter
		for _, c := range x.AlterTableStmt.Cmds {
			cmd := c.GetAlterTableCmd()
			if cmd == nil {
				continue
			}
			switch cmd.Subtype {
			case pg_query.AlterTableType_AT_ChangeOwner:
				t = TypeRole
			case pg_query.AlterTableType_AT_DropColumn:
				if t != TypeRole {
					t = TypeAlterDropColumn
				}
			}
		}
		return f(t)
	case *pg_query.Node_RenameStmt, *pg_query.Node_CommentStmt, *pg_query.Node_SecLabelStmt,
		*pg_query.Node_AlterSeqStmt, *pg_query.Node_AlterDomainStmt, *pg_query.Node_AlterEnumStmt,
		*pg_query.Node_AlterFunctionStmt, *pg_query.Node_AlterExtensionStmt,
		*pg_query.Node_AlterExtensionContentsStmt, *pg_query.Node_AlterObjectSchemaStmt,
		*pg_query.Node_AlterObjectDependsStmt, *pg_query.Node_AlterTableMoveAllStmt,
		*pg_query.Node_AlterTypeStmt, *pg_query.Node_AlterCollationStmt, *pg_query.Node_AlterStatsStmt,
		*pg_query.Node_AlterPolicyStmt, *pg_query.Node_AlterOperatorStmt,
		*pg_query.Node_AlterTsdictionaryStmt, *pg_query.Node_AlterTsconfigurationStmt,
		*pg_query.Node_AlterOpFamilyStmt, *pg_query.Node_ReplicaIdentityStmt:
		return f(TypeDDLAlter)

	case *pg_query.Node_CreateStmt, *pg_query.Node_IndexStmt, *pg_query.Node_ViewStmt,
		*pg_query.Node_CreateSeqStmt, *pg_query.Node_CompositeTypeStmt, *pg_query.Node_CreateEnumStmt,
		*pg_query.Node_CreateRangeStmt, *pg_query.Node_CreateFunctionStmt,
		*pg_query.Node_CreateExtensionStmt, *pg_query.Node_CreateSchemaStmt,
		*pg_query.Node_CreateDomainStmt, *pg_query.Node_DefineStmt, *pg_query.Node_CreateTrigStmt,
		*pg_query.Node_RuleStmt, *pg_query.Node_CreatePolicyStmt, *pg_query.Node_CreateStatsStmt,
		*pg_query.Node_CreateForeignTableStmt, *pg_query.Node_CreateCastStmt,
		*pg_query.Node_CreateOpClassStmt, *pg_query.Node_CreateOpFamilyStmt,
		*pg_query.Node_CreateConversionStmt:
		return f(TypeDDLCreate)

	case *pg_query.Node_GrantStmt, *pg_query.Node_GrantRoleStmt,
		*pg_query.Node_AlterDefaultPrivilegesStmt:
		return f(TypeGrant)
	case *pg_query.Node_CreateRoleStmt, *pg_query.Node_AlterRoleStmt, *pg_query.Node_AlterRoleSetStmt,
		*pg_query.Node_DropRoleStmt, *pg_query.Node_AlterOwnerStmt, *pg_query.Node_ReassignOwnedStmt,
		*pg_query.Node_DropOwnedStmt:
		return f(TypeRole)

	case *pg_query.Node_VariableSetStmt:
		return f(classifySet(x.VariableSetStmt))
	case *pg_query.Node_VariableShowStmt:
		return f(TypeSession)
	case *pg_query.Node_ListenStmt, *pg_query.Node_UnlistenStmt, *pg_query.Node_DeallocateStmt,
		*pg_query.Node_DiscardStmt, *pg_query.Node_ConstraintsSetStmt:
		return f(TypeSession)
	case *pg_query.Node_TransactionStmt:
		switch x.TransactionStmt.Kind {
		case pg_query.TransactionStmtKind_TRANS_STMT_BEGIN, pg_query.TransactionStmtKind_TRANS_STMT_START,
			pg_query.TransactionStmtKind_TRANS_STMT_COMMIT, pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK,
			pg_query.TransactionStmtKind_TRANS_STMT_SAVEPOINT, pg_query.TransactionStmtKind_TRANS_STMT_RELEASE,
			pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK_TO:
			return f(TypeTransaction)
		}
		return f(TypeUnknown)

	case *pg_query.Node_CopyStmt:
		c := x.CopyStmt
		switch {
		case c.IsProgram:
			return f(TypeCopyProgram)
		case c.Filename != "":
			return f(TypeCopyFile)
		case c.IsFrom:
			return f(TypeCopyFromStdin)
		}
		return f(TypeCopyToStdout)

	case *pg_query.Node_DoStmt, *pg_query.Node_CallStmt:
		return f(TypeExecuteBlock)
	case *pg_query.Node_VacuumStmt, *pg_query.Node_ReindexStmt, *pg_query.Node_ClusterStmt,
		*pg_query.Node_RefreshMatViewStmt, *pg_query.Node_CheckPointStmt, *pg_query.Node_LoadStmt:
		return f(TypeMaintenance)
	case *pg_query.Node_LockStmt:
		return f(TypeLock)
	case *pg_query.Node_NotifyStmt:
		return f(TypeNotify)
	}
	// PREPARE/EXECUTE, ALTER SYSTEM, CREATE/ALTER DATABASE, tablespaces,
	// FDW/servers/user mappings, publications/subscriptions, event triggers,
	// languages, access methods, IMPORT FOREIGN SCHEMA, ...
	return f(TypeUnknown)
}

func classifySet(v *pg_query.VariableSetStmt) string {
	if v.Kind == pg_query.VariableSetKind_VAR_RESET_ALL {
		return TypeUnknown
	}
	name := strings.ToLower(v.Name)
	switch {
	case roleGUCs[name]:
		return TypeSetRole
	case sessionGUCs[name]:
		return TypeSession
	}
	return TypeUnknown
}

// stableBuiltins are built-in functions that are IMMUTABLE or STABLE: within
// one statement snapshot they return the same result for the same input.
// Anything else in a WHERE clause (random(), nextval(), clock_timestamp(),
// user-defined functions of unknown volatility, ...) makes the WHERE
// volatile. The list is deliberately small; a missing entry only costs a
// snapshot (fail closed), never correctness.
var stableBuiltins = map[string]bool{
	// time (STABLE within a transaction)
	"now": true, "statement_timestamp": true, "transaction_timestamp": true,
	"date_trunc": true, "date_part": true, "extract": true, "age": true, "timezone": true,
	"to_timestamp": true, "to_date": true, "to_char": true, "to_number": true,
	"make_interval": true, "make_date": true, "make_time": true, "make_timestamp": true,
	"make_timestamptz": true, "justify_days": true, "justify_hours": true, "isfinite": true,
	"overlaps": true,
	// strings
	"lower": true, "upper": true, "length": true, "char_length": true, "character_length": true,
	"octet_length": true, "bit_length": true, "md5": true, "sha256": true, "btrim": true,
	"ltrim": true, "rtrim": true, "substr": true, "substring": true, "position": true,
	"strpos": true, "replace": true, "left": true, "right": true, "lpad": true, "rpad": true,
	"reverse": true, "initcap": true, "split_part": true, "starts_with": true, "concat": true,
	"concat_ws": true, "regexp_replace": true, "regexp_match": true, "regexp_like": true,
	"translate": true, "ascii": true, "chr": true, "format": true, "encode": true, "decode": true,
	"convert_from": true, "current_setting": true,
	// numbers
	"abs": true, "round": true, "floor": true, "ceil": true, "ceiling": true, "trunc": true,
	"mod": true, "power": true, "sqrt": true, "sign": true,
	// arrays / json
	"array_length": true, "array_position": true, "array_positions": true, "array_to_string": true,
	"string_to_array": true, "array_lower": true, "array_upper": true, "cardinality": true,
	"unnest": true, "generate_series": true,
	"jsonb_extract_path": true, "jsonb_extract_path_text": true, "json_extract_path": true,
	"json_extract_path_text": true, "jsonb_typeof": true, "json_typeof": true,
	"jsonb_array_length": true, "json_array_length": true, "to_jsonb": true, "to_json": true,
	"jsonb_build_object": true, "json_build_object": true,
	// aggregates used in subqueries
	"count": true, "sum": true, "min": true, "max": true, "avg": true, "bool_and": true,
	"bool_or": true, "every": true, "array_agg": true, "string_agg": true,
	// function-style casts
	"date": true, "text": true, "int2": true, "int4": true, "int8": true, "numeric": true,
	"float4": true, "float8": true, "bool": true, "varchar": true, "timestamp": true,
	"timestamptz": true,
}

// StableBuiltin reports whether fn (as listed in Statement.Functions) is a
// built-in known to be IMMUTABLE or STABLE.
func StableBuiltin(fn string) bool { return stableBuiltins[fn] }
