// Package commap is the communication map (docs/PHASE5_DESIGN.md §2): a
// rollup worker folds decided actions and delegation hops into 5-minute
// edges between typed nodes, marks hidden signals, and an auditor API serves
// views (team, agent, swarm, external, blast radius), path traces, time
// replay and live updates.
//
// The map stores node ids, verbs, counts, byte totals, data labels and
// sample action ids: never payload contents.
package commap

import (
	"net"
	"regexp"
	"strings"
)

// Node kinds (the prefix of a node id).
const (
	KindAgent    = "agent"
	KindInstance = "instance"
	KindUser     = "user"
	KindApp      = "app"
	KindStore    = "store"
	KindMemory   = "memory"
	KindMCP      = "mcp"
	KindDomain   = "domain"
)

// Structural verbs (not data flow): a sponsor owns an agent; an agent runs
// an instance. Path traces never follow them.
const (
	VerbOwns = "OWNS"
	VerbRuns = "RUNS"
)

// Edge classes, worst last. "hidden" outranks red: a hidden signal is the
// one thing on an edge the console must never let blend in.
const (
	ClassGreen  = "green"
	ClassYellow = "yellow"
	ClassRed    = "red"
	ClassHidden = "hidden"
)

func classRank(c string) int {
	switch c {
	case ClassGreen:
		return 0
	case ClassYellow:
		return 1
	case ClassRed:
		return 2
	case ClassHidden:
		return 3
	}
	return 2 // unknown: treated as red (fail closed)
}

func worse(a, b string) string {
	if classRank(b) > classRank(a) {
		return b
	}
	return a
}

var (
	agentIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	systemPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	upstreamPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,62}$`)
	memStorePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	namespacePat    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	mcpServerPat    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	hostPattern     = regexp.MustCompile(`^[a-z0-9*]([a-z0-9-]{0,62})?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	emailPattern    = regexp.MustCompile(`^[a-z0-9.!#$%&'*+/=?^_{|}~-]{1,64}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	labelPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)
	teamPattern     = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)
)

// Special domain nodes.
const (
	DomainUnknown = "unknown" // recipients not known (fail closed: counted external)
	DomainAnyone  = "anyone"  // a Drive "anyone with the link" share
	DomainAny     = "*"       // blast radius: any external host
)

// AgentNode and friends build typed node ids. They return "" when the
// component is not a well-formed id, so a malformed target never becomes a
// node the console would render or a path query could be steered by.
func AgentNode(id string) string {
	if !agentIDPattern.MatchString(id) {
		return ""
	}
	return KindAgent + ":" + id
}

func InstanceNode(id string) string {
	if !agentIDPattern.MatchString(id) {
		return ""
	}
	return KindInstance + ":" + id
}

func UserNode(email string) string {
	e := strings.ToLower(strings.TrimSpace(email))
	if len(e) > 254 || !emailPattern.MatchString(e) {
		return ""
	}
	return KindUser + ":" + e
}

func AppNode(system string) string {
	if !systemPattern.MatchString(system) {
		return ""
	}
	return KindApp + ":" + system
}

func PostgresStoreNode(upstream string) string {
	if !upstreamPattern.MatchString(upstream) {
		return ""
	}
	return KindStore + ":postgres:" + upstream
}

func MemoryNode(store, namespace string) string {
	if !memStorePattern.MatchString(store) || (namespace != "*" && !namespacePat.MatchString(namespace)) {
		return ""
	}
	return KindMemory + ":" + store + "/" + namespace
}

func MCPNode(server string) string {
	if !mcpServerPat.MatchString(server) {
		return ""
	}
	return KindMCP + ":" + server
}

// DomainNode normalises a host (lowercase, no trailing dot, no port).
func DomainNode(host string) string {
	h := normHost(host)
	switch h {
	case DomainUnknown, DomainAnyone, DomainAny:
		return KindDomain + ":" + h
	}
	if ip := net.ParseIP(h); ip != nil {
		return KindDomain + ":" + ip.String()
	}
	if h == "" || len(h) > 253 || !hostPattern.MatchString(h) {
		return ""
	}
	return KindDomain + ":" + h
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// NodeKind returns the kind prefix of a node id ("" when malformed).
func NodeKind(id string) string {
	k, _, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	return k
}

// ValidNode reports whether id is a well-formed typed node id: the API
// accepts only these as query parameters.
func ValidNode(id string) bool {
	if len(id) > 300 {
		return false
	}
	kind, rest, ok := strings.Cut(id, ":")
	if !ok {
		return false
	}
	switch kind {
	case KindAgent:
		return AgentNode(rest) == id
	case KindInstance:
		return InstanceNode(rest) == id
	case KindUser:
		return UserNode(rest) == id
	case KindApp:
		return AppNode(rest) == id
	case KindStore:
		sys, name, ok := strings.Cut(rest, ":")
		return ok && sys == "postgres" && PostgresStoreNode(name) == id
	case KindMemory:
		st, ns, ok := strings.Cut(rest, "/")
		return ok && MemoryNode(st, ns) == id
	case KindMCP:
		return MCPNode(rest) == id
	case KindDomain:
		return DomainNode(rest) == id
	}
	return false
}

// nodeLabel is the display label of a node (the id without its kind).
func nodeLabel(id string) string {
	_, rest, _ := strings.Cut(id, ":")
	return rest
}

// ValidLabel reports whether l is a well-formed data label (as normalised by
// action.Normalize: lowercase).
func ValidLabel(l string) bool { return labelPattern.MatchString(l) }
