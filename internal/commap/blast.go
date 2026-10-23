package commap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"fortik/internal/access"
)

// capability levels of a reach edge.
const (
	capNone = iota
	capRead
	capReadWrite
)

func capName(c int) string {
	switch c {
	case capRead:
		return "read"
	case capReadWrite:
		return "read_write"
	}
	return "none"
}

// reachItem is one target the agent's current access can reach.
type reachItem struct {
	system   string
	to       string
	granted  string
	cap      int
	external bool
	detail   map[string]any
}

// Systems Fortik governs without an access profile (hook-classified); the
// blast radius cannot list their reach, only what the agent did.
var unprofiledSystems = []string{"files", "shell"}

// reach computes the blast radius halo of agentID from its current access
// profiles, the overrides in force (agent and team), memory access, its
// control level and suspension, and its live credentials. It returns the
// agent node id and one "reach" edge per target.
func (s *Service) reach(ctx context.Context, tx pgx.Tx, agentID string) (string, []Edge, []string, error) {
	agent := AgentNode(agentID)
	var (
		team      string
		level     int
		suspended bool
	)
	err := tx.QueryRow(ctx, `SELECT business_unit, level, suspended_at IS NOT NULL FROM agents WHERE agent_id = $1`, agentID).
		Scan(&team, &level, &suspended)
	if errors.Is(err, pgx.ErrNoRows) {
		// Seen on the map but not registered: Fortik refuses all of its
		// actions (POL-015), so nothing is reachable through Fortik.
		return agent, []Edge{}, unprofiledSystems, nil
	}
	if err != nil {
		return "", nil, nil, fmt.Errorf("blast agent: %w", err)
	}

	var items []reachItem
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (system) system, version, profile_json FROM access_profiles
		WHERE agent_id = $1 ORDER BY system, version DESC`, agentID)
	if err != nil {
		return "", nil, nil, fmt.Errorf("blast profiles: %w", err)
	}
	type prof struct {
		system  string
		version int
		raw     json.RawMessage
	}
	var profs []prof
	for rows.Next() {
		var p prof
		if err := rows.Scan(&p.system, &p.version, &p.raw); err != nil {
			rows.Close()
			return "", nil, nil, err
		}
		profs = append(profs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", nil, nil, err
	}
	hasHTTP := false
	for _, p := range profs {
		items = append(items, profileReach(p.system, p.version, p.raw)...)
		hasHTTP = hasHTTP || p.system == "http"
	}
	// Without an http profile external browsing (READ) is open by default
	// (fortik.access http_open_default; POL-028 restricts it only once a
	// profile exists): any external domain is reachable for reading, and a
	// query string can carry data out (POL-671 watches it).
	if !hasHTTP {
		items = append(items, reachItem{system: "http", to: DomainNode(DomainAny), cap: capRead, external: true,
			granted: "no http profile: external READ open by default"})
	}

	// Memory: per-agent memory access over every configured memory store.
	memMode := "full"
	if err := tx.QueryRow(ctx, `SELECT mode FROM memory_access WHERE agent_id = $1`, agentID).Scan(&memMode); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil, fmt.Errorf("blast memory access: %w", err)
	}
	stores, err := tx.Query(ctx, `SELECT substr(key, 8) FROM integrations WHERE system = 'memory' AND key LIKE 'memory:%' ORDER BY key`)
	if err != nil {
		return "", nil, nil, fmt.Errorf("blast memory stores: %w", err)
	}
	storeNames, err := pgx.CollectRows(stores, pgx.RowTo[string])
	if err != nil {
		return "", nil, nil, err
	}
	for _, st := range storeNames {
		to := MemoryNode(st, "*")
		if to == "" {
			continue
		}
		c := capReadWrite
		switch memMode {
		case "none":
			c = capNone
		case "staging_only":
			c = capReadWrite // writes land in staging, reviewed before promotion
		case "full":
		default:
			c = capNone // unknown mode: fail closed
		}
		items = append(items, reachItem{system: "memory", to: to, granted: "memory_access:" + memMode, cap: c,
			detail: map[string]any{"memory_access": memMode}})
	}

	// Overrides in force for the agent or its team.
	type ov struct{ id, system, mode string }
	var ovs []ov
	orows, err := tx.Query(ctx, `SELECT override_id, system, mode FROM access_overrides
		WHERE status IN ('active', 'blocked')
		  AND ((scope = 'agent' AND scope_id = $1) OR ($2 <> '' AND scope = 'team' AND scope_id = $2))
		ORDER BY override_id`, agentID, team)
	if err != nil {
		return "", nil, nil, fmt.Errorf("blast overrides: %w", err)
	}
	for orows.Next() {
		var o ov
		if err := orows.Scan(&o.id, &o.system, &o.mode); err != nil {
			orows.Close()
			return "", nil, nil, err
		}
		ovs = append(ovs, o)
	}
	orows.Close()
	if err := orows.Err(); err != nil {
		return "", nil, nil, err
	}

	creds := map[string]int{}
	crows, err := tx.Query(ctx, `SELECT system, count(*)::int FROM credential_issuances
		WHERE agent_id = $1 AND revoked_at IS NULL AND expires_at > now() GROUP BY system`, agentID)
	if err != nil {
		return "", nil, nil, fmt.Errorf("blast credentials: %w", err)
	}
	for crows.Next() {
		var sys string
		var n int
		if err := crows.Scan(&sys, &n); err != nil {
			crows.Close()
			return "", nil, nil, err
		}
		creds[sys] = n
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return "", nil, nil, err
	}

	lvl := levelName(level)
	out := make([]Edge, 0, len(items))
	for _, it := range items {
		eff := it.cap
		var limits []string
		for _, o := range ovs {
			if o.system != it.system {
				continue
			}
			switch o.mode {
			case "read_only":
				if eff > capRead {
					eff = capRead
				}
				limits = append(limits, fmt.Sprintf("override %s: %s read_only", o.id, o.system))
			default: // suspended, or an unknown mode (fail closed)
				eff = capNone
				limits = append(limits, fmt.Sprintf("override %s: %s suspended", o.id, o.system))
			}
		}
		switch {
		case lvl == "KILLED" || lvl == "QUARANTINED":
			eff = capNone
			limits = append(limits, "agent is "+lvl)
		case suspended:
			eff = capNone
			limits = append(limits, "agent is suspended")
		case lvl == "ISOLATED":
			if it.external {
				eff = capNone
			} else {
				eff = min(eff, capRead)
			}
			limits = append(limits, "agent is ISOLATED (internal reads only)")
		case lvl == "READ_ONLY":
			eff = min(eff, capRead)
			limits = append(limits, "agent is READ_ONLY")
		}
		d := it.detail
		if d == nil {
			d = map[string]any{}
		}
		if n := creds[it.system]; n > 0 {
			d["live_credentials"] = n
		}
		if it.external {
			d["external"] = true
		}
		out = append(out, Edge{Reach: true, Labels: []string{}, SampleActionIDs: []string{}, From: agent, To: it.to, Verb: "REACH", System: it.system, Granted: it.granted,
			Effective: capName(eff), Limits: limits, Detail: d})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].System != out[j].System {
			return out[i].System < out[j].System
		}
		return out[i].To < out[j].To
	})
	return agent, out, unprofiledSystems, nil
}

func sendCap(mode string) int {
	if mode == access.SendNone {
		return capNone
	}
	return capReadWrite
}

func modeCap(mode string) int {
	switch mode {
	case access.ModeReadOnly:
		return capRead
	case access.ModeReadWrite:
		return capReadWrite
	}
	return capNone
}

// profileReach lists the targets one current profile version grants.
func profileReach(system string, version int, raw json.RawMessage) []reachItem {
	src := fmt.Sprintf("profile %s v%d", system, version)
	v, err := access.Parse(system, raw)
	if err != nil {
		// A stored profile that no longer validates is enforced as no
		// access by policy; it is shown, not guessed at.
		to := AppNode(system)
		if to == "" {
			return nil
		}
		return []reachItem{{system: system, to: to, granted: src + ": invalid", cap: capNone,
			detail: map[string]any{"error": "profile does not validate"}}}
	}
	var out []reachItem
	switch p := v.(type) {
	case access.GmailProfile:
		c := sendCap(p.Send)
		if c == capNone && p.Read != nil && *p.Read {
			c = capRead
		}
		d := map[string]any{"send": p.Send, "read": p.Read != nil && *p.Read}
		if p.MaxRecipients != nil {
			d["max_recipients"] = *p.MaxRecipients
		}
		out = append(out, reachItem{system: system, to: AppNode("gmail"), granted: src + ": send " + p.Send, cap: c, detail: d})
		if p.Send == access.SendAny {
			out = append(out, reachItem{system: system, to: DomainNode(DomainAny), granted: src + ": send any", cap: capReadWrite,
				external: true, detail: map[string]any{"via": "app:gmail"}})
		}
	case access.DriveProfile:
		out = append(out, reachItem{system: system, to: AppNode("drive"), granted: src + ": " + p.Mode + ", share " + p.Share,
			cap: modeCap(p.Mode), detail: map[string]any{"mode": p.Mode, "share": p.Share}})
		if p.Share == access.SendAny && p.Mode == access.ModeReadWrite {
			out = append(out, reachItem{system: system, to: DomainNode(DomainAny), granted: src + ": share any", cap: capReadWrite,
				external: true, detail: map[string]any{"via": "app:drive"}})
		}
	case access.GitHubProfile:
		c := capNone
		for _, perm := range p.Permissions {
			if perm == access.PermWrite {
				c = capReadWrite
			} else if c == capNone {
				c = capRead
			}
		}
		if len(p.Repos) == 0 {
			c = capNone
		}
		repos := p.Repos
		if len(repos) > 50 {
			repos = repos[:50]
		}
		out = append(out, reachItem{system: system, to: AppNode("github"), granted: src, cap: c,
			detail: map[string]any{"repos": repos, "repos_total": len(p.Repos), "permissions": p.Permissions}})
	case access.AWSProfile:
		out = append(out, reachItem{system: system, to: AppNode("aws"), granted: src + ": " + p.Mode, cap: modeCap(p.Mode),
			detail: map[string]any{"services": p.Services, "denied_actions": p.DeniedActions}})
	case access.PostgresProfile:
		names := make([]string, 0, len(p.Upstreams))
		for u := range p.Upstreams {
			names = append(names, u)
		}
		sort.Strings(names)
		for _, u := range names {
			if to := PostgresStoreNode(u); to != "" {
				out = append(out, reachItem{system: system, to: to, granted: src + ": " + p.Upstreams[u], cap: modeCap(p.Upstreams[u])})
			}
		}
	case access.A2AProfile:
		for _, a := range p.MayDelegateTo {
			to := AgentNode(a)
			if a == access.Wildcard {
				to = KindAgent + ":*"
			}
			if to != "" {
				out = append(out, reachItem{system: system, to: to, granted: src + ": may delegate", cap: capReadWrite,
					detail: map[string]any{"max_depth": p.MaxDepth}})
			}
		}
	case access.HTTPProfile:
		switch p.External {
		case access.ExternalAny:
			out = append(out, reachItem{system: system, to: DomainNode(DomainAny), granted: src + ": external any", cap: capReadWrite, external: true})
		case access.ExternalAllowlist:
			for _, d := range p.AllowedDomains {
				if to := DomainNode(d); to != "" {
					out = append(out, reachItem{system: system, to: to, granted: src + ": allowlist", cap: capReadWrite, external: true})
				}
			}
		}
	case access.MCPProfile:
		names := make([]string, 0, len(p.Servers))
		for srv := range p.Servers {
			names = append(names, srv)
		}
		sort.Strings(names)
		for _, srv := range names {
			if to := MCPNode(srv); to != "" {
				tools := p.Servers[srv]
				out = append(out, reachItem{system: system, to: to, granted: src + ": tools " + strings.Join(tools, ","),
					cap: capReadWrite, detail: map[string]any{"tools": tools}})
			}
		}
	}
	return out
}
