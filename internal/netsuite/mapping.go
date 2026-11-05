package netsuite

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"fortik/internal/action"
)

// Operations (target.operation).
const (
	OpGet       = "get"
	OpList      = "list"
	OpCreate    = "create"
	OpUpdate    = "update"
	OpUpsert    = "upsert"
	OpDelete    = "delete"
	OpTransform = "transform"
	OpQuery     = "query"
)

const (
	recordPrefix = "/services/rest/record/v1/"
	maxFields    = 100
	maxTables    = 32
)

var (
	recordTypeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,99}$`)
	recordIDRe   = regexp.MustCompile(`^([0-9]{1,18}|eid:[A-Za-z0-9_.:-]{1,100})$`)
	fieldRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,99}$`)
	tableRe      = regexp.MustCompile(`(?i)\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

// Request is a mapped NetSuite REST request.
type Request struct {
	Key           string // the connection (tenant) it goes to
	IntegrationID string
	Verb          action.Verb
	Path          string // NetSuite path, e.g. /services/rest/record/v1/vendor/12
	RawQuery      string
	Operation     string
	RecordType    string // lower-cased
	RecordID      string
	ToType        string
	Fields        []string
	Tables        []string
	Limit         int
	Reason        string // why it is UNKNOWN
}

// Target is the action target (never field values).
func (m Request) Target() map[string]any {
	t := map[string]any{"operation": m.Operation, "path": clip(m.Path, 300)}
	if m.RecordType != "" {
		t["record_type"] = m.RecordType
	}
	if m.RecordID != "" {
		t["record_id"] = m.RecordID
	}
	if m.ToType != "" {
		t["to_record_type"] = m.ToType
	}
	if m.Fields != nil {
		t["fields"] = m.Fields
	}
	if m.Operation == OpQuery {
		t["query_tables"] = nonNil(m.Tables)
		t["limit"] = m.Limit
	}
	if m.Reason != "" {
		t["unclassified"] = m.Reason
	}
	return t
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// MapRequest classifies one agent request. path is the NetSuite path (the
// gateway prefix already removed). Anything not recognised is UNKNOWN, which
// policy refuses (POL-002): never forwarded on a guess.
func MapRequest(method, path, rawQuery string, body []byte) Request {
	m := Request{Path: path, RawQuery: rawQuery, Verb: "UNKNOWN"}
	unknown := func(why string) Request { m.Verb, m.Operation, m.Reason = "UNKNOWN", "unknown", why; return m }
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return unknown("path traversal")
	}
	if path == suiteqlPath {
		if method != http.MethodPost {
			return unknown("SuiteQL accepts POST only")
		}
		var q struct {
			Q string `json:"q"`
		}
		if err := json.Unmarshal(body, &q); err != nil || strings.TrimSpace(q.Q) == "" {
			return unknown("SuiteQL body is not {\"q\": \"...\"}")
		}
		m.Verb, m.Operation = action.VerbRead, OpQuery
		m.Tables = queryTables(q.Q)
		m.Limit = 1000
		if v, err := url.ParseQuery(rawQuery); err == nil {
			if n, err := strconv.Atoi(v.Get("limit")); err == nil && n > 0 {
				m.Limit = n
			}
		}
		return m
	}
	rest, ok := strings.CutPrefix(path, recordPrefix)
	if !ok {
		return unknown("not a record or SuiteQL endpoint")
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) == 0 || !recordTypeRe.MatchString(parts[0]) {
		return unknown("malformed record type")
	}
	m.RecordType = strings.ToLower(parts[0])
	if len(parts) >= 2 {
		if !recordIDRe.MatchString(parts[1]) {
			return unknown("malformed record id")
		}
		m.RecordID = parts[1]
	}
	switch {
	case len(parts) == 1 && method == http.MethodGet:
		m.Verb, m.Operation = action.VerbRead, OpList
	case len(parts) == 1 && method == http.MethodPost:
		m.Verb, m.Operation = action.VerbWrite, OpCreate
	case len(parts) == 2 && method == http.MethodGet:
		m.Verb, m.Operation = action.VerbRead, OpGet
	case len(parts) == 2 && method == http.MethodPatch:
		m.Verb, m.Operation = action.VerbWrite, OpUpdate
	case len(parts) == 2 && method == http.MethodPut:
		m.Verb, m.Operation = action.VerbWrite, OpUpsert
	case len(parts) == 2 && method == http.MethodDelete:
		m.Verb, m.Operation = action.VerbDelete, OpDelete
	case len(parts) == 4 && parts[2] == "!transform" && method == http.MethodPost && recordTypeRe.MatchString(parts[3]):
		m.Verb, m.Operation, m.ToType = action.VerbWrite, OpTransform, strings.ToLower(parts[3])
	case len(parts) >= 3 && method == http.MethodGet:
		// Sublists and sub-resources of one record (e.g. /vendor/12/addressBook).
		m.Verb, m.Operation = action.VerbRead, OpGet
	default:
		return unknown("unsupported method or record path")
	}
	if m.Verb == action.VerbWrite {
		fields, ok := topLevelFields(body)
		if !ok {
			return unknown("record body is not a JSON object with plain field names")
		}
		m.Fields = fields
	}
	return m
}

func topLevelFields(body []byte) ([]string, bool) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return []string{}, true
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(obj))
	for k := range obj {
		if !fieldRe.MatchString(k) {
			return nil, false
		}
		out = append(out, strings.ToLower(k))
	}
	if len(out) > maxFields {
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

// queryTables lists the tables a SuiteQL statement names after FROM/JOIN,
// lower-cased. It is a lexical summary for policy, not a SQL parser: a query
// whose tables cannot be found reports none, and policy treats that as
// unknown (a restricted profile refuses it).
func queryTables(q string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range tableRe.FindAllStringSubmatch(q, -1) {
		t := strings.ToLower(m[1])
		if !seen[t] && len(out) < maxTables {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
