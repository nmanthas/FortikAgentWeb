package nsquickstart

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"fortik/internal/action"
	"fortik/internal/integrations"
)

// Catalog is what the last successful check learned, used to validate a call.
type Catalog struct {
	Tools         map[string]storedTool
	Current       bool   // discovered for the current settings and token
	ServerID      string // server name @ endpoint host
	Key           string // the connection
	System        string // netsuite_quickstart | netsuite_mcp
	IntegrationID string // the logical integration (tenant)
}

const (
	maxNames   = 200
	maxNameLen = 128
)

// Normalize expresses one tools/call as a Fortik action (system netsuite,
// transport mcp). Only names, ids, counts and hashes go into the target,
// never field values. Anything that cannot be understood is said so in the
// target (understood=false, schema_errors, tool_offered=false) for policy to
// decide; it never becomes a guess.
func (m *Mapping) Normalize(tool string, args json.RawMessage, cat Catalog) action.Action {
	system := cat.System
	if system == "" {
		system = IntegrationKey
	}
	t := map[string]any{
		"transport":       Transport,
		"integration":     system, // the connection type; integration_id is the tenant
		"server_id":       cat.ServerID,
		"tool":            clip(tool, maxNameLen),
		"mapping_version": m.Version,
	}
	if cat.IntegrationID != "" {
		t["integration_id"] = cat.IntegrationID
	}
	if cat.Key != "" {
		t["connection"] = cat.Key
	}
	a := action.Action{System: providerOf(system), Target: t, PayloadSummary: action.PayloadSummary{Bytes: int64(len(args))}}
	cls, mapped := m.Tools[tool]
	if !mapped {
		a.Verb = "UNKNOWN"
		t["reason"] = "tool is not in the " + mappingLabel(system) + " tool mapping " + m.Version
		return a
	}
	a.Verb = cls.Verb
	t["operation"] = cls.Operation

	canon, obj, perr := canonical(args)
	t["args_sha256"] = hashHex(canon)
	st, offered := cat.Tools[tool]
	t["tool_offered"] = offered
	t["catalog_current"] = cat.Current
	if offered {
		t["schema_hash"] = st.Hash
	}
	var problems []string
	if perr != "" {
		problems = append(problems, perr)
	} else if offered {
		problems = append(problems, validateArgs(st.InputSchema, obj)...)
	}
	if len(problems) > 0 {
		t["schema_errors"] = problems
	}
	var notUnderstood []string
	extract(cls.Operation, tool, obj, t, &notUnderstood)
	t["understood"] = len(notUnderstood) == 0
	if len(notUnderstood) > 0 {
		t["not_understood"] = notUnderstood
	}
	if cls.Operation == "send_email" {
		if n, ok := t["recipient_overrides"].(int); ok {
			a.PayloadSummary.Recipients = n
		}
	}
	return a
}

// extract fills the target from the arguments of each operation.
func extract(op, tool string, a map[string]json.RawMessage, t map[string]any, nu *[]string) {
	str := func(k string) (string, bool) {
		var s string
		if json.Unmarshal(a[k], &s) == nil {
			return s, true
		}
		return "", false
	}
	id := func(k string) (string, bool) {
		raw, ok := a[k]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return clip(s, maxNameLen), true
		}
		var n json.Number
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&n) == nil {
			return n.String(), true
		}
		return "", false
	}
	if rt, ok := str("recordType"); ok && rt != "" {
		t["record_type"] = strings.ToLower(clip(rt, maxNameLen))
	}
	if rid, ok := id("id"); ok {
		t["record_id"] = rid
	}
	switch op {
	case "list":
		if n, ok := intArg(a, "limit"); ok {
			t["limit"] = n
		}
	case "create", "update":
		fields, sublists, scalar, bad := fieldNames(a["fieldValues"], a["sublistValues"])
		if bad != "" {
			*nu = append(*nu, bad)
		}
		t["fields"] = fields
		if len(sublists) > 0 {
			t["sublists"] = sublists
		}
		if op == "update" {
			if _, ok := t["record_id"]; !ok {
				*nu = append(*nu, "update names no record id")
			}
			if len(fields) == 0 && len(sublists) == 0 {
				*nu = append(*nu, "update names no fields or sublists")
			}
			// Undo is possible only for plain body fields with scalar values:
			// Fortik reads them before the update and writes them back.
			t["undo_possible"] = scalar && len(sublists) == 0 && len(fields) > 0 && bad == ""
		}
	case "delete":
		if _, ok := t["record_id"]; !ok {
			*nu = append(*nu, "delete names no record id")
		}
	case "record_action":
		if v, ok := str("actionId"); ok && v != "" {
			t["action_id"] = clip(v, maxNameLen)
		} else {
			*nu = append(*nu, "record action without an actionId")
		}
		t["parameters"] = keys(a["parameters"])
	case "transform":
		if rt, ok := str("sourceRecordType"); ok && rt != "" {
			t["record_type"] = strings.ToLower(clip(rt, maxNameLen))
		}
		if rid, ok := id("sourceId"); ok {
			t["record_id"] = rid
		}
		if v, ok := str("transformId"); ok && v != "" {
			t["transform_id"] = strings.ToLower(clip(v, maxNameLen))
		} else {
			*nu = append(*nu, "transform without a transformId")
		}
		fields, sublists, _, bad := fieldNames(a["fieldValues"], a["sublistValues"])
		if bad != "" {
			*nu = append(*nu, bad)
		}
		t["fields"] = fields
		if len(sublists) > 0 {
			t["sublists"] = sublists
		}
	case "attachment":
		if v, ok := str("operation"); ok && v != "" {
			t["attachment_operation"] = strings.ToLower(clip(v, 32))
		} else {
			*nu = append(*nu, "attachment change without an operation")
		}
	case "upload_temp_file":
		if v, ok := str("fileName"); ok {
			if i := strings.LastIndexByte(v, '.'); i >= 0 && len(v)-i <= 10 {
				t["file_extension"] = strings.ToLower(v[i+1:])
			}
		}
		if v, ok := str("contentType"); ok {
			t["content_type"] = clip(strings.ToLower(v), 100)
		}
		if v, ok := str("fileBytes"); ok {
			t["file_bytes"] = len(v) * 3 / 4
		}
	case "send_email":
		if v, ok := str("actionId"); ok && v != "" {
			t["email_action"] = clip(v, maxNameLen)
		}
		n, domains, ids := 0, map[string]bool{}, 0
		overridden := false
		for _, k := range []string{"to", "cc", "bcc"} {
			raw, ok := a[k]
			if !ok {
				continue
			}
			overridden = true
			var list []map[string]json.RawMessage
			if json.Unmarshal(raw, &list) != nil {
				*nu = append(*nu, k+" is not a recipient list")
				continue
			}
			for _, r := range list {
				n++
				var e string
				if json.Unmarshal(r["email"], &e) == nil && e != "" {
					if at := strings.LastIndexByte(e, '@'); at > 0 {
						domains[strings.ToLower(e[at+1:])] = true
					}
				} else {
					ids++
				}
			}
		}
		t["recipient_override"] = overridden
		t["recipient_overrides"] = n
		t["recipient_entity_ids"] = ids
		t["recipient_domains"] = sortedKeys(domains)
		var attach bool
		if json.Unmarshal(a["attachPdf"], &attach) != nil {
			attach = true // the tool's default
		}
		t["attach_pdf"] = attach
	case "preference_read", "preference_write":
		if v, ok := str("preferenceKey"); ok && v != "" {
			t["preference_key"] = strings.ToUpper(clip(v, 64))
		} else if op == "preference_write" {
			*nu = append(*nu, "preference change without a preferenceKey")
		}
	case "report":
		if v, ok := str("reportId"); ok && v != "" {
			t["report_id"] = clip(v, maxNameLen)
		}
	case "dismiss_notification":
		count := 0
		if _, ok := a["notificationId"]; ok {
			count = 1
		}
		var ids []json.RawMessage
		if json.Unmarshal(a["notificationIds"], &ids) == nil {
			count += len(ids)
		}
		t["notifications"] = count
	case "support_request":
		if v, ok := str("queryType"); ok {
			t["query_type"] = strings.ToUpper(clip(v, 16))
		}
		if v, ok := str("description"); ok {
			t["description_length"] = len(v)
		}
	}
}

// fieldNames lists the body field names (subrecord fields as
// "subrecord.field") and sublist line field names ("sublist.field") a write
// sets, lower-cased and sorted; scalar reports whether every body value is a
// scalar (string, number, boolean or null).
func fieldNames(fv, sv json.RawMessage) (fields, sublists []string, scalar bool, bad string) {
	names := map[string]bool{}
	scalar = true
	if len(fv) > 0 && string(fv) != "null" {
		var body map[string]json.RawMessage
		if json.Unmarshal(fv, &body) != nil {
			return nil, nil, false, "fieldValues is not an object"
		}
		for k, v := range body {
			k = strings.ToLower(clip(k, maxNameLen))
			names[k] = true
			v = bytes.TrimSpace(v)
			if len(v) > 0 && (v[0] == '{' || v[0] == '[') {
				scalar = false
				var sub struct {
					FieldValues map[string]json.RawMessage `json:"fieldValues"`
				}
				if json.Unmarshal(v, &sub) == nil {
					for sk := range sub.FieldValues {
						names[k+"."+strings.ToLower(clip(sk, maxNameLen))] = true
					}
				}
			}
		}
	}
	subs := map[string]bool{}
	if len(sv) > 0 && string(sv) != "null" {
		var lists map[string]json.RawMessage
		if json.Unmarshal(sv, &lists) != nil {
			return sortedKeys(names), nil, false, "sublistValues is not an object"
		}
		for k, v := range lists {
			k = strings.ToLower(clip(k, maxNameLen))
			subs[k] = true
			// create: [line, ...]; update: {mode, lines: [line, ...]}
			var lines []map[string]json.RawMessage
			if json.Unmarshal(v, &lines) != nil {
				var env struct {
					Lines []map[string]json.RawMessage `json:"lines"`
				}
				if json.Unmarshal(v, &env) != nil {
					return sortedKeys(names), sortedKeys(subs), false, "sublist " + k + " is not a list of lines"
				}
				lines = env.Lines
			}
			for _, line := range lines {
				src := line
				if inner, ok := line["fieldValues"]; ok {
					var m map[string]json.RawMessage
					if json.Unmarshal(inner, &m) == nil {
						src = m
					}
				}
				for lk := range src {
					switch lk {
					case "id", "uniqueKey", "templateKey", "fieldValues":
						continue
					}
					names[k+"."+strings.ToLower(clip(lk, maxNameLen))] = true
				}
			}
		}
	}
	return capNames(sortedKeys(names)), capNames(sortedKeys(subs)), scalar, ""
}

// canonical re-encodes arguments with sorted keys and exact numbers, so the
// same arguments always hash the same (approval grants are bound to it).
func canonical(args json.RawMessage) ([]byte, map[string]json.RawMessage, string) {
	if len(bytes.TrimSpace(args)) == 0 || string(bytes.TrimSpace(args)) == "null" {
		return []byte("{}"), map[string]json.RawMessage{}, ""
	}
	d := json.NewDecoder(bytes.NewReader(args))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil || d.More() {
		return args, nil, "arguments are not valid JSON"
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return args, nil, "arguments must be a JSON object"
	}
	b, _ := json.Marshal(obj)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	return b, raw, ""
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func intArg(a map[string]json.RawMessage, k string) (int64, bool) {
	var n json.Number
	d := json.NewDecoder(bytes.NewReader(a[k]))
	d.UseNumber()
	if d.Decode(&n) != nil {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func keys(raw json.RawMessage) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return []string{}
	}
	out := map[string]bool{}
	for k := range m {
		out[strings.ToLower(clip(k, maxNameLen))] = true
	}
	return capNames(sortedKeys(out))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capNames(s []string) []string {
	if len(s) > maxNames {
		return s[:maxNames]
	}
	return s
}

// serverID names the upstream server for the action target.
func serverID(name, endpoint string) string {
	host := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	if name == "" {
		name = "unknown"
	}
	return fmt.Sprintf("%s@%s", clip(name, 64), clip(host, 128))
}

// mappingLabel names a connection type's tool mapping in reasons.
func mappingLabel(system string) string {
	switch system {
	case integrations.SystemNetSuiteMCP:
		return "NetSuite AI Connector"
	case integrations.SystemNetSuiteQuickStart, "":
		return "QuickStart"
	}
	return kindTitle(system)
}
