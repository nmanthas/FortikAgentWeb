package commap

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"fortik/internal/action"
)

// Hidden-signal kinds (docs/PHASE5_DESIGN.md §2, "Hidden signals").
const (
	SignalLabelIntoMemory = "label_into_memory"        // 1. a data label flows into a memory write
	SignalEncodedParam    = "encoded_url_param"        // 2. encoded payload in a URL parameter (POL-671)
	SignalLabelToEgress   = "labelled_to_egress_agent" // 3. labelled data passed to an agent with external egress
)

// actionRow is the part of an actions row the rollup reads.
type actionRow struct {
	ID         string
	AgentID    string
	InstanceID string
	System     string
	Verb       string
	Class      string
	Decision   string
	RuleID     string
	Target     map[string]any
	Summary    action.PayloadSummary
	Matched    []string // rule ids that fired (decision_json.matched)
	TS         time.Time
	Sponsor    string // agents.sponsor at rollup time ("" when unregistered)
}

// edgeKey identifies one edge row.
type edgeKey struct {
	Window time.Time
	From   string
	To     string
	Verb   string
}

// signal is one hidden signal on one contribution (summaries only).
type signal struct {
	Kind   string
	Detail map[string]any
}

// contrib is one action's (or delegation's) contribution to one edge.
type contrib struct {
	Key      edgeKey
	Bytes    int64
	Labels   []string
	Class    string
	ActionID string // "" when the source has no action (delegation without one)
	AgentID  string // the acting agent
	Decision string
	Signals  []signal
	// egressTo is set on an a2a DELEGATE to another agent that carries
	// labels: the receiving agent, checked for external egress (signal 3).
	egressTo string
	// Origin is set on a hub -> domain egress contribution: the agent whose
	// call it was (recorded in edge_links for exact path attribution).
	Origin string
}

var verbPattern = regexp.MustCompile(`^[A-Z_]{1,32}$`)

// mapper turns one action into edge contributions.
type mapper struct {
	window time.Duration
	// internalMail: the Google Workspace primary and internal domains; nil
	// when the integration is not configured (every recipient domain then
	// counts as external, exactly as the gateway classifies it).
	internalMail     map[string]bool
	memoryMCPServers map[string]bool
	sensitive        map[string]bool // nil = every data label counts
	encodedMin       int
}

// windowStart floors ts to the window, aligned to the Unix epoch.
func windowStart(ts time.Time, w time.Duration) time.Time {
	sec := int64(w / time.Second)
	u := ts.UTC().Unix()
	m := u % sec
	if m < 0 {
		m += sec
	}
	return time.Unix(u-m, 0).UTC()
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func domainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.Trim(addr[i+1:], "<> "))), ".")
}

func validLabels(in []string) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		if ValidLabel(l) && !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// flagged returns the labels that count for hidden signals.
func (m *mapper) flagged(labels []string) []string {
	if m.sensitive == nil {
		return labels
	}
	var out []string
	for _, l := range labels {
		if m.sensitive[l] {
			out = append(out, l)
		}
	}
	return out
}

func (m *mapper) external(domain string) bool {
	return m.internalMail == nil || !m.internalMail[domain]
}

// edges maps one action to its edge contributions: the main edge (agent ->
// target), egress fan-out to external domains through the app that carried
// the data, the agent -> instance edge and the sponsor -> agent edge.
func (m *mapper) edges(a actionRow) []contrib {
	agent := AgentNode(a.AgentID)
	if agent == "" {
		return nil
	}
	ws := windowStart(a.TS, m.window)
	verb := a.Verb
	if !verbPattern.MatchString(verb) {
		verb = "UNKNOWN"
	}
	class := a.Class
	switch class {
	case ClassGreen, ClassYellow, ClassRed:
	default:
		class = ClassRed
	}
	labels := validLabels(a.Summary.DataLabels)
	bytes := max(a.Summary.Bytes, 0)
	t := a.Target
	if t == nil {
		t = map[string]any{}
	}
	ext := t["external"] == true

	to := ""
	switch a.System {
	case action.SystemPostgres:
		to = PostgresStoreNode(str(t["upstream"]))
	case action.SystemMemory:
		to = MemoryNode(str(t["store"]), str(t["namespace"]))
	case action.SystemMCP:
		to = MCPNode(str(t["server"]))
	case action.SystemA2A:
		to = AgentNode(str(t["to_agent"]))
	case "agents":
		to = InstanceNode(str(t["instance_id"]))
	case action.SystemHTTP:
		if ext {
			to = DomainNode(str(t["domain"]))
		}
	}
	if to == "" {
		to = AppNode(a.System)
	}
	if to == "" {
		return nil
	}

	var sigs []signal
	if p := FindEncodedParams(t, m.encodedMin); len(p) > 0 || slices.Contains(a.Matched, RuleEncodedParam) {
		d := map[string]any{"rule_id": RuleEncodedParam}
		if len(p) > 0 {
			d["params"] = p[:min(len(p), 5)]
		} else {
			d["note"] = "policy finding only"
		}
		sigs = append(sigs, signal{Kind: SignalEncodedParam, Detail: d})
	}
	if fl := m.flagged(labels); len(fl) > 0 && m.memoryWrite(a, verb, t) {
		sigs = append(sigs, signal{Kind: SignalLabelIntoMemory, Detail: map[string]any{"labels": fl}})
	}

	base := contrib{Bytes: bytes, Labels: labels, Class: class, ActionID: a.ID, AgentID: a.AgentID, Decision: a.Decision}
	main := base
	main.Key = edgeKey{ws, agent, to, verb}
	main.Signals = sigs
	if a.System == action.SystemA2A && verb == string(action.VerbDelegate) && NodeKind(to) == KindAgent && to != agent &&
		len(m.flagged(labels)) > 0 {
		main.egressTo = nodeLabel(to)
	}
	out := []contrib{main}

	// Egress through the app that carried the data: hub -> domain.
	for _, d := range m.egressDomains(a, verb, t, ext) {
		c := base
		c.Key = edgeKey{ws, to, d, verb}
		c.Signals = sigs
		c.Origin = agent
		out = append(out, c)
	}
	if inst := InstanceNode(a.InstanceID); inst != "" {
		c := base
		c.Key, c.Labels, c.Bytes = edgeKey{ws, agent, inst, VerbRuns}, nil, 0
		out = append(out, c)
	}
	if u := UserNode(a.Sponsor); u != "" {
		c := base
		c.Key, c.Labels, c.Bytes, c.Class = edgeKey{ws, u, agent, VerbOwns}, nil, 0, ClassGreen
		out = append(out, c)
	}
	return out
}

func (m *mapper) memoryWrite(a actionRow, verb string, t map[string]any) bool {
	switch a.System {
	case action.SystemMemory:
		return verb == string(action.VerbRemember) || verb == string(action.VerbWrite)
	case action.SystemMCP:
		return m.memoryMCPServers[str(t["server"])] && (verb == string(action.VerbRemember) || verb == string(action.VerbWrite))
	}
	return false
}

// egressDomains lists the external domain nodes an action's data went to
// through an app (Gmail recipients and forwarding, Drive shares, any other
// app with target.external and target.domain). HTTP goes to its domain
// directly (the main edge), so it has no fan-out.
func (m *mapper) egressDomains(a actionRow, verb string, t map[string]any, ext bool) []string {
	var hosts []string
	add := func(h string) {
		if n := DomainNode(h); n != "" && !slices.Contains(hosts, n) {
			hosts = append(hosts, n)
		}
	}
	switch a.System {
	case action.SystemHTTP:
		return nil
	case action.SystemGmail:
		if t["recipients_unknown"] == true {
			add(DomainUnknown)
		}
		for _, k := range []string{"to", "cc", "bcc"} {
			for _, addr := range strList(t[k]) {
				if d := domainOf(addr); d != "" && m.external(d) {
					add(d)
				}
			}
		}
		if f := str(t["forward_to"]); f != "" {
			if d := domainOf(f); d != "" && m.external(d) {
				add(d)
			} else if d == "" {
				add(DomainUnknown)
			}
		}
	case action.SystemDrive:
		if !ext {
			break
		}
		switch str(t["share_type"]) {
		case "user", "group":
			if d := domainOf(str(t["grantee"])); d != "" {
				add(d)
			} else {
				add(DomainUnknown)
			}
		case "domain":
			if g := str(t["grantee"]); g != "" {
				add(g)
			} else {
				add(DomainUnknown)
			}
		case "anyone":
			add(DomainAnyone)
		default:
			add(DomainUnknown)
		}
	default:
		if ext {
			if d := str(t["domain"]); d != "" {
				add(d)
			}
		}
	}
	sort.Strings(hosts)
	if len(hosts) > maxEgressPerAction {
		hosts = hosts[:maxEgressPerAction]
	}
	return hosts
}

// maxEgressPerAction bounds the fan-out of one action (a mail to hundreds of
// domains is still one action; the first domains in order are drawn).
const maxEgressPerAction = 50
