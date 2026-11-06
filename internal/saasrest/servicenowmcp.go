package saasrest

// Fortik's MCP endpoint over a ServiceNow REST connection:
// /mcp/servicenow_rest/<tenant>.
//
// For instances without ServiceNow's own MCP server (MCP Server Console needs
// Now Assist; personal developer instances do not have it), an MCP client
// (Claude Desktop through mcp-remote, an IDE, an agent framework) reads and
// changes records with four tools. Each tool call becomes the equivalent
// Table API call on the gateway (/gw/servicenow/api/now/table/...) and is
// dispatched in-process through the gateway's decision pipeline: the agent's
// ServiceNow profile, holds, approvals, suspensions and audit apply exactly as
// to the same REST call. There is deliberately no delete tool.
//
// <tenant> names the ServiceNow integration (servicenow:<tenant>; "default"
// for the connection keyed plain servicenow). This endpoint is separate from
// /mcp/servicenow/<tenant>, which relays to ServiceNow's own MCP server.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"fortik/internal/authz"
	"fortik/internal/integrations"
)

// ServiceNowMCPPath is the endpoint's pattern on the gateway.
const ServiceNowMCPPath = "/mcp/servicenow_rest/{name}"

// ServiceNowMCP serves the ServiceNow (REST) MCP endpoint.
type ServiceNowMCP struct {
	dispatch Dispatcher
	version  string
}

// NewServiceNowMCP builds the endpoint over a gateway dispatcher.
func (s *Service) NewServiceNowMCP(d Dispatcher, version string) *ServiceNowMCP {
	return &ServiceNowMCP{dispatch: d, version: version}
}

// Mount registers the endpoint on the gateway's agent-authenticated mux.
func (m *ServiceNowMCP) Mount(mount func(pattern string, h http.HandlerFunc)) {
	mountMCP(mount, ServiceNowMCPPath, m.serve)
}

func (m *ServiceNowMCP) serve(w http.ResponseWriter, r *http.Request) {
	serveMCP(w, r, mcpSpec{
		route:   "/mcp/servicenow_rest/<tenant>",
		title:   "ServiceNow",
		server:  "fortik-servicenow",
		version: m.version,
		instructions: "Read and change ServiceNow records through Fortik's REST connection. Every call is checked by Fortik before it reaches ServiceNow. " +
			"Reads are allowed for the tables the agent may use. Creates and updates are HELD for human approval and NOT executed: tell the user to approve " +
			"the action in the Fortik console (Approvals), then call the same tool again with exactly the same arguments. Records cannot be deleted here.",
		tools: snTools,
		call:  m.call,
	})
}

const (
	snMaxLimit      = 100
	snDefaultLimit  = 10
	snMaxOffset     = 100000
	snMaxQuery      = 2000
	snMaxFields     = 50
	snMaxValues     = 100
	snMaxValueChars = 20000
	snMaxText       = 60000 // characters of records returned to the model
)

var (
	snTable     = regexp.MustCompile(`^[A-Za-z0-9_]{1,80}$`)
	snSysID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	snField     = regexp.MustCompile(`^[A-Za-z0-9_]{1,80}$`)
	snFieldPath = regexp.MustCompile(`^[A-Za-z0-9_]{1,80}(\.[A-Za-z0-9_]{1,80}){0,4}$`)
)

var (
	snTableArg = map[string]any{"type": "string", "description": "The table's name, e.g. incident, change_request, sys_user (not its label)."}
	snSysIDArg = map[string]any{"type": "string", "description": "The record's sys_id (32 lower-case hex characters)."}
	snFieldArg = map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": snMaxFields,
		"description": "Fields to return, e.g. [\"number\",\"short_description\",\"state\"]; dot-walking (caller_id.email) works. Omit for every field."}
	snDisplayArg = map[string]any{"type": "boolean", "description": "Return display values (names instead of sys_ids, labels instead of codes). Default true."}
	snValuesArg  = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": []string{"string", "number", "boolean"}},
		"description": "Field names and the values to set, e.g. {\"short_description\":\"Printer jam\",\"urgency\":\"2\"}."}
)

var snTools = []map[string]any{
	{
		"name": "servicenow_query_table",
		"description": "List records of a ServiceNow table, optionally filtered by an encoded query (e.g. active=true^priority=1^ORDERBYDESCsys_created_on). " +
			"Returns at most `limit` records; page with `offset`.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"table":          snTableArg,
				"query":          map[string]any{"type": "string", "description": "A ServiceNow encoded query (sysparm_query). Omit for all records."},
				"fields":         snFieldArg,
				"limit":          map[string]any{"type": "integer", "minimum": 1, "maximum": snMaxLimit, "description": "Records to return (default 10, at most 100)."},
				"offset":         map[string]any{"type": "integer", "minimum": 0, "description": "Records to skip, for paging."},
				"display_values": snDisplayArg,
			},
			"required":             []string{"table"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "servicenow_get_record",
		"description": "Read one ServiceNow record by its sys_id.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"table":          snTableArg,
				"sys_id":         snSysIDArg,
				"fields":         snFieldArg,
				"display_values": snDisplayArg,
			},
			"required":             []string{"table", "sys_id"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name": "servicenow_create_record",
		"description": "Create a ServiceNow record. Fortik holds it for human approval first: after it is approved in the Fortik console, call this tool " +
			"again with exactly the same table and values to create it.",
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"table": snTableArg, "values": snValuesArg},
			"required":             []string{"table", "values"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false},
	},
	{
		"name": "servicenow_update_record",
		"description": "Change fields of a ServiceNow record. Fortik holds it for human approval first: after it is approved in the Fortik console, call this " +
			"tool again with exactly the same table, sys_id and values to apply it.",
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"table": snTableArg, "sys_id": snSysIDArg, "values": snValuesArg},
			"required":             []string{"table", "sys_id", "values"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true},
	},
}

// snAllowed are each tool's arguments; anything else is refused.
var snAllowed = map[string][]string{
	"servicenow_query_table":   {"table", "query", "fields", "limit", "offset", "display_values"},
	"servicenow_get_record":    {"table", "sys_id", "fields", "display_values"},
	"servicenow_create_record": {"table", "values"},
	"servicenow_update_record": {"table", "sys_id", "values"},
}

type snArgs struct {
	Table         string
	SysID         string
	Query         string
	Fields        []string
	Limit, Offset int
	DisplayValues bool
	Values        map[string]any
}

// parseSNArgs checks a tool's arguments; the error is shown to the model.
func parseSNArgs(tool string, raw json.RawMessage) (snArgs, error) {
	a := snArgs{Limit: snDefaultLimit, DisplayValues: true}
	allowed, ok := snAllowed[tool]
	if !ok {
		return a, fmt.Errorf("unknown tool %s", clip(tool, 80))
	}
	m := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &m); err != nil {
			return a, fmt.Errorf("arguments must be a JSON object")
		}
	}
	for k := range m {
		if !slices.Contains(allowed, k) {
			return a, fmt.Errorf("unknown argument %q (allowed: %s)", clip(k, 40), strings.Join(allowed, ", "))
		}
	}
	str := func(k string, dst *string) error {
		if v, ok := m[k]; ok && json.Unmarshal(v, dst) != nil {
			return fmt.Errorf("%s must be a string", k)
		}
		return nil
	}
	if err := str("table", &a.Table); err != nil {
		return a, err
	}
	if !snTable.MatchString(a.Table) {
		return a, fmt.Errorf("table must be a table name such as incident (letters, digits and _)")
	}
	if slices.Contains(allowed, "sys_id") {
		if err := str("sys_id", &a.SysID); err != nil {
			return a, err
		}
		if !snSysID.MatchString(a.SysID) {
			return a, fmt.Errorf("sys_id must be the record's 32-character sys_id")
		}
	}
	if err := str("query", &a.Query); err != nil {
		return a, err
	}
	if len(a.Query) > snMaxQuery {
		return a, fmt.Errorf("query is longer than %d characters", snMaxQuery)
	}
	if v, ok := m["fields"]; ok {
		if json.Unmarshal(v, &a.Fields) != nil {
			return a, fmt.Errorf("fields must be a list of field names")
		}
		if len(a.Fields) > snMaxFields {
			return a, fmt.Errorf("at most %d fields", snMaxFields)
		}
		for _, f := range a.Fields {
			if !snFieldPath.MatchString(f) {
				return a, fmt.Errorf("field %q is not a field name", clip(f, 40))
			}
		}
	}
	num := func(k string, dst *int, lo, hi int) error {
		v, ok := m[k]
		if !ok {
			return nil
		}
		var n json.Number
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber()
		if d.Decode(&n) != nil {
			return fmt.Errorf("%s must be a whole number", k)
		}
		i, err := strconv.Atoi(n.String())
		if err != nil || i < lo || i > hi {
			return fmt.Errorf("%s must be a whole number from %d to %d", k, lo, hi)
		}
		*dst = i
		return nil
	}
	if err := num("limit", &a.Limit, 1, snMaxLimit); err != nil {
		return a, err
	}
	if err := num("offset", &a.Offset, 0, snMaxOffset); err != nil {
		return a, err
	}
	if v, ok := m["display_values"]; ok && json.Unmarshal(v, &a.DisplayValues) != nil {
		return a, fmt.Errorf("display_values must be true or false")
	}
	if slices.Contains(allowed, "values") {
		v, ok := m["values"]
		if !ok {
			return a, fmt.Errorf("values is required: the fields to set")
		}
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber() // numbers are passed on exactly as given
		if d.Decode(&a.Values) != nil || a.Values == nil {
			return a, fmt.Errorf("values must be an object of field names and values")
		}
		if len(a.Values) == 0 || len(a.Values) > snMaxValues {
			return a, fmt.Errorf("values must set 1 to %d fields", snMaxValues)
		}
		for k, x := range a.Values {
			if !snField.MatchString(k) {
				return a, fmt.Errorf("%q is not a field name", clip(k, 40))
			}
			switch t := x.(type) {
			case string:
				if len(t) > snMaxValueChars {
					return a, fmt.Errorf("the value of %s is longer than %d characters", k, snMaxValueChars)
				}
			case json.Number, bool:
			default:
				return a, fmt.Errorf("the value of %s must be a string, number or boolean", k)
			}
		}
	}
	return a, nil
}

// readQuery is the Table API query string of a read.
func (a snArgs) readQuery(list bool) string {
	v := url.Values{}
	if list {
		if a.Query != "" {
			v.Set("sysparm_query", a.Query)
		}
		v.Set("sysparm_limit", strconv.Itoa(a.Limit))
		if a.Offset > 0 {
			v.Set("sysparm_offset", strconv.Itoa(a.Offset))
		}
	}
	if len(a.Fields) > 0 {
		v.Set("sysparm_fields", strings.Join(a.Fields, ","))
	}
	v.Set("sysparm_display_value", strconv.FormatBool(a.DisplayValues))
	v.Set("sysparm_exclude_reference_link", "true")
	return v.Encode()
}

func (m *ServiceNowMCP) call(ctx context.Context, w http.ResponseWriter, req mcpReq, pr authz.Principal, tenant string, hdr http.Header) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		rpcError(w, req.ID, -32602, "invalid tools/call parameters")
		return
	}
	if _, ok := snAllowed[params.Name]; !ok {
		rpcError(w, req.ID, -32602, "unknown tool "+clip(params.Name, 80))
		return
	}
	a, err := parseSNArgs(params.Name, params.Arguments)
	if err != nil {
		toolResult(w, req.ID, true, "", "", "invalid arguments: "+err.Error(), nil)
		return
	}
	gw := func(method, path string, body any) gwResult {
		return gwCall(ctx, m.dispatch, pr, hdr, integrations.SystemServiceNow, tenant, method, path, body)
	}
	base := "/api/now/table/" + a.Table
	switch params.Name {
	case "servicenow_query_table":
		g := gw(http.MethodGet, base+"?"+a.readQuery(true), nil)
		if g.status >= 300 {
			toolResult(w, req.ID, true, g.actionID, g.decision(), g.problem("Reading "+a.Table), nil)
			return
		}
		var res struct {
			Result []json.RawMessage `json:"result"`
		}
		if json.Unmarshal(g.body, &res) != nil {
			toolResult(w, req.ID, true, g.actionID, "allow", "ServiceNow answered with something other than a record list", nil)
			return
		}
		text, cut := recordLines(res.Result)
		head := fmt.Sprintf("%d record(s) from %s", len(res.Result), a.Table)
		if a.Offset > 0 {
			head += fmt.Sprintf(" starting at offset %d", a.Offset)
		}
		if len(res.Result) == 0 {
			head = "No records from " + a.Table + " (none match, or the integration user's ACLs hide them)."
		} else if len(res.Result) == a.Limit {
			head += fmt.Sprintf("; more may exist (call again with offset %d)", a.Offset+a.Limit)
		}
		if cut {
			head += "; the list was cut short, ask for fewer fields or records"
		}
		toolResult(w, req.ID, false, g.actionID, "allow", head+":\n"+text,
			map[string]any{"table": a.Table, "count": len(res.Result), "offset": a.Offset, "truncated": cut})
	case "servicenow_get_record":
		g := gw(http.MethodGet, base+"/"+a.SysID+"?"+a.readQuery(false), nil)
		if g.status == http.StatusNotFound && g.refusal == nil {
			toolResult(w, req.ID, true, g.actionID, "allow", "No "+a.Table+" record with sys_id "+a.SysID+" (or the integration user cannot read it).", nil)
			return
		}
		if g.status >= 300 {
			toolResult(w, req.ID, true, g.actionID, g.decision(), g.problem("Reading "+a.Table+" "+a.SysID), nil)
			return
		}
		rec, ok := snRecord(g.body)
		if !ok {
			toolResult(w, req.ID, true, g.actionID, "allow", "ServiceNow answered with something other than a record", nil)
			return
		}
		toolResult(w, req.ID, false, g.actionID, "allow", clip(string(rec), snMaxText), map[string]any{"table": a.Table, "sys_id": a.SysID})
	case "servicenow_create_record", "servicenow_update_record":
		method, path, what := http.MethodPost, base, "Creating a "+a.Table+" record"
		if params.Name == "servicenow_update_record" {
			method, path, what = http.MethodPatch, base+"/"+a.SysID, "Updating "+a.Table+" "+a.SysID
		}
		g := gw(method, path, a.Values)
		structured := map[string]any{"table": a.Table}
		if a.SysID != "" {
			structured["sys_id"] = a.SysID
		}
		if g.status >= 300 {
			text := g.problem(what)
			if g.held() {
				text += fmt.Sprintf(" Fortik action id: %s. Ask a human to approve it in the Fortik console (Approvals); then call %s again with exactly the same arguments.",
					g.actionID, params.Name)
			}
			toolResult(w, req.ID, true, g.actionID, g.decision(), text, structured)
			return
		}
		rec, _ := snRecord(g.body)
		var f struct {
			SysID  any `json:"sys_id"`
			Number any `json:"number"`
		}
		_ = json.Unmarshal(rec, &f)
		id, num := plain(f.SysID), plain(f.Number)
		if id != "" {
			structured["sys_id"] = id
		}
		if num != "" {
			structured["number"] = num
		}
		done := "Created " + a.Table + " record"
		if params.Name == "servicenow_update_record" {
			done = "Updated " + a.Table + " record"
		}
		if num != "" {
			done += " " + num
		}
		if id != "" {
			done += " (sys_id " + id + ")"
		}
		if len(rec) > 0 {
			done += ":\n" + clip(string(rec), snMaxText)
		}
		toolResult(w, req.ID, false, g.actionID, "allow", done, structured)
	}
}

// snRecord is the record of a Table API answer ({"result": {...}}).
func snRecord(body []byte) (json.RawMessage, bool) {
	var res struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(body, &res) != nil || len(res.Result) == 0 || res.Result[0] != '{' {
		return nil, false
	}
	return res.Result, true
}

// recordLines is one compact JSON record per line, cut at snMaxText.
func recordLines(recs []json.RawMessage) (string, bool) {
	var b strings.Builder
	for i, r := range recs {
		var c bytes.Buffer
		if json.Compact(&c, r) != nil {
			c.Reset()
			c.Write(r)
		}
		if b.Len()+c.Len()+1 > snMaxText {
			fmt.Fprintf(&b, "… %d more record(s) not shown", len(recs)-i)
			return b.String(), true
		}
		b.Write(c.Bytes())
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n"), false
}

// plain is a field's value as text, whether ServiceNow sent the value itself
// or {"value": ..., "display_value": ...}.
func plain(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["value"].(string); ok {
			return s
		}
	}
	return ""
}
