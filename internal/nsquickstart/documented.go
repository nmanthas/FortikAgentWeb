package nsquickstart

import "slices"

// Oracle's documented QuickStart MCP tool lists ("Set up the QuickStart MCP
// server", read 2026-10-25). Documentation, not a guarantee: the live
// server's tools/list is what Fortik records, and Oracle notes the set is
// growing. Used only to explain a token's likely scope, never to allow a
// call.
var (
	DocumentedReadTools = []string{"notifications", "navigation_targets", "todo_list", "get_record_model", "list_records", "read_record",
		"read_record_sublist", "get_record_apply_candidates", "list_record_attachments", "discover_preferences", "read_preferences",
		"report_catalog", "describe_report", "report_filter_values", "configure_report", "run_report"}
	DocumentedWriteTools = []string{"create_record", "dismiss_notification", "update_record", "delete_record", "execute_record_action",
		"execute_record_transform", "upload_temporary_file", "set_record_attachment", "send_record_email", "set_preferences",
		"submit_contact_support_request"}
)

// Token scope as Fortik can tell it from the tool list.
const (
	ModeReadOnly   = "read_only"
	ModeReadWrite  = "read_write"
	ModeUnverified = "unverified" // tools outside the documented lists: the scope cannot be told
	ModeUnknown    = "unknown"    // never discovered
)

// Documented access of one tool name.
const (
	DocReadOnlyToken  = "read_only_token"  // documented for read-only tokens
	DocReadWriteToken = "read_write_token" // documented only for read-write tokens
	DocUndocumented   = "undocumented"
)

func documentedAccess(name string) string {
	switch {
	case slices.Contains(DocumentedReadTools, name):
		return DocReadOnlyToken
	case slices.Contains(DocumentedWriteTools, name):
		return DocReadWriteToken
	}
	return DocUndocumented
}

// inferMode says what the discovered tool names establish about the
// token's scope. Oracle documents that write tools are exposed only to
// read-write credentials, so any of them means read-write. Without them the
// token is read-only only if every tool is a documented read tool: an
// undocumented tool could write.
func inferMode(names []string) (string, string) {
	var write, undocumented []string
	for _, n := range names {
		switch documentedAccess(n) {
		case DocReadWriteToken:
			write = append(write, n)
		case DocUndocumented:
			undocumented = append(undocumented, n)
		}
	}
	switch {
	case len(names) == 0:
		return ModeUnknown, "no tools were discovered"
	case len(write) > 0:
		return ModeReadWrite, "the server exposes tools Oracle documents only for read-write tokens: " + list(write)
	case len(undocumented) > 0:
		return ModeUnverified, "no documented write tool is exposed, but these tools are not in Oracle's documented lists, so the token's scope cannot be established from the tool list: " + list(undocumented)
	default:
		return ModeReadOnly, "every exposed tool is in Oracle's documented read-only list and no write tool is exposed (inferred from tools/list; QuickStart does not report the token's scope)"
	}
}

func list(s []string) string {
	const max = 12
	out := ""
	for i, n := range s {
		if i == max {
			return out + ", ..."
		}
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
