package netsuite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"fortik/internal/broker"
	"fortik/internal/coverage"
	"fortik/internal/integrations"
	"fortik/internal/saas"
)

// DefaultActivityQuery reads record changes from NetSuite's system notes with
// SuiteQL. {cursor} is the last system note id seen and {entities} the mapped
// agents' entity ids (both inserted as validated integers). Only metadata is
// read (who, which record, which field, when): never old or new values.
// Its table and column names follow NetSuite's SuiteQL schema as documented;
// Test connection verifies them in the actual account before they are used.
const DefaultActivityQuery = `SELECT id, date, field, name, recordid, recordtypeid, role, context FROM systemnote WHERE id > {cursor} AND name IN ({entities}) ORDER BY id`

var digitsRe = regexp.MustCompile(`^[0-9]{1,18}$`)

// Probe is one capability check against the real account.
type Probe struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Connector implements saas.Connector for one NetSuite account.
type Connector struct {
	src    integrations.Source
	client *Client
	log    *slog.Logger
	now    func() time.Time
}

var (
	_ saas.Connector      = (*Connector)(nil)
	_ broker.Adapter      = (*Connector)(nil)
	_ integrations.Tester = (*Connector)(nil)
)

// NewConnector shares the gateway adapter's client (one token cache).
func NewConnector(src integrations.Source, client *Client, log *slog.Logger) *Connector {
	if client == nil {
		client = NewClient(nil)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Connector{src: src, client: client, log: log, now: time.Now}
}

func (c *Connector) System() string { return System }

// settings is the single tenant the saas.Connector interface works on: the
// only NetSuite REST connection (or the legacy key). With several tenants
// use tenants().
func (c *Connector) settings(ctx context.Context) (Settings, error) {
	list, err := c.src.List(ctx, System)
	if err != nil {
		return Settings{}, err
	}
	switch len(list) {
	case 0:
		r, err := c.src.Get(ctx, IntegrationKey)
		if err != nil {
			return Settings{}, err
		}
		return SettingsFrom(r)
	case 1:
		return SettingsFrom(list[0])
	}
	return Settings{}, fmt.Errorf("netsuite: %d tenants are connected: name one", len(list))
}

// Tenant is one NetSuite REST connection's settings, or why they are unusable.
type Tenant struct {
	Settings Settings
	Err      error
}

// tenants returns every NetSuite REST connection.
func (c *Connector) tenants(ctx context.Context) ([]Tenant, error) {
	list, err := c.src.List(ctx, System)
	if err != nil {
		return nil, err
	}
	out := make([]Tenant, 0, len(list))
	for _, r := range list {
		s, err := SettingsFrom(r)
		if s.Key == "" {
			s.Key, s.IntegrationID = r.Key, r.IntegrationID
		}
		out = append(out, Tenant{Settings: s, Err: err})
	}
	return out, nil
}

// Probes checks, in the real account, each capability this connector relies
// on: token issuance, SuiteQL, the activity (system notes) query, and each
// mapped agent's entity. It never writes anything.
func (c *Connector) Probes(ctx context.Context) ([]Probe, error) {
	s, err := c.settings(ctx)
	if err != nil {
		return nil, err
	}
	return c.probes(ctx, s), nil
}

func (c *Connector) probes(ctx context.Context, s Settings) []Probe {
	var out []Probe
	if _, err := c.client.Token(ctx, s); err != nil {
		return append(out, Probe{Name: "oauth2_client_credentials", Detail: err.Error()})
	}
	out = append(out, Probe{Name: "oauth2_client_credentials", OK: true, Detail: "access token issued for " + s.AccountID})
	if _, _, err := c.client.SuiteQL(ctx, s, "SELECT id FROM employee", 1, 0); err != nil {
		out = append(out, Probe{Name: "suiteql", Detail: err.Error()})
	} else {
		out = append(out, Probe{Name: "suiteql", OK: true, Detail: "SuiteQL query on employee succeeded"})
	}
	q, err := activityQuery(s, "0", []string{"0"})
	if err != nil {
		out = append(out, Probe{Name: "activity_system_notes", Detail: err.Error()})
	} else if _, _, err := c.client.SuiteQL(ctx, s, q, 1, 0); err != nil {
		out = append(out, Probe{Name: "activity_system_notes", Detail: "the activity query failed in this account (set a working one in Integrations): " + err.Error()})
	} else {
		out = append(out, Probe{Name: "activity_system_notes", OK: true, Detail: "system notes readable with the configured query"})
	}
	inv, err := c.inventory(ctx, s)
	switch {
	case err != nil:
		out = append(out, Probe{Name: "agent_entities", Detail: err.Error()})
	case len(s.AgentMap) == 0:
		out = append(out, Probe{Name: "agent_entities", Detail: "no agents mapped (Integrations > NetSuite > Agents)"})
	default:
		found := 0
		for _, a := range inv.Agents {
			if a.Status != "not found" {
				found++
			}
		}
		out = append(out, Probe{Name: "agent_entities", OK: found == len(inv.Agents),
			Detail: fmt.Sprintf("%d of %d mapped agent entities found as employees", found, len(inv.Agents))})
	}
	out = append(out, Probe{Name: "agent_inventory_api", OK: false,
		Detail: "no documented NetSuite API for listing AI agents was verified; agents are mapped to the entity they act as"})
	return out
}

// Test is the integration's "Test connection": token and SuiteQL must work.
func (c *Connector) Test(ctx context.Context, r integrations.Resolved) error {
	s, err := SettingsFrom(r)
	if err != nil {
		return err
	}
	for _, p := range c.probes(ctx, s) {
		if (p.Name == "oauth2_client_credentials" || p.Name == "suiteql") && !p.OK {
			return fmt.Errorf("%s: %s", p.Name, p.Detail)
		}
	}
	return nil
}

// Health implements saas.Connector.
func (c *Connector) Health(ctx context.Context) (saas.Tenant, error) {
	s, err := c.settings(ctx)
	if err != nil {
		return saas.Tenant{}, err
	}
	if _, err := c.client.Token(ctx, s); err != nil {
		return saas.Tenant{}, err
	}
	return saas.Tenant{System: System, TenantID: s.AccountID}, nil
}

// Inventory implements saas.Connector: the mapped agents, each checked as an
// employee record. Complete is false: NetSuite exposes no verified agent
// inventory, so agents NOT mapped cannot be listed.
func (c *Connector) Inventory(ctx context.Context) (saas.Inventory, error) {
	s, err := c.settings(ctx)
	if err != nil {
		return saas.Inventory{}, err
	}
	return c.inventory(ctx, s)
}

func (c *Connector) inventory(ctx context.Context, s Settings) (saas.Inventory, error) {
	inv := saas.Inventory{Tenant: saas.Tenant{System: System, TenantID: s.AccountID}, Complete: false, SyncedAt: c.now().UTC(),
		Note: "agents are those mapped in Integrations > NetSuite > Agents; NetSuite exposes no verified API that lists AI agents", Agents: []saas.InventoryAgent{}}
	if len(s.AgentMap) == 0 {
		return inv, nil
	}
	ids := entityIDs(s)
	rows, _, err := c.client.SuiteQL(ctx, s, "SELECT id, entityid, isinactive FROM employee WHERE id IN ("+strings.Join(ids, ",")+")", 1000, 0)
	if err != nil {
		return inv, fmt.Errorf("agent entities: %w", err)
	}
	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[fmt.Sprint(r["id"])] = r
	}
	agents := make([]string, 0, len(s.AgentMap))
	for a := range s.AgentMap {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, a := range agents {
		e := s.AgentMap[a]
		ia := saas.InventoryAgent{NativeID: e, Name: a, Principal: "entity " + e, Status: "not found"}
		if r, ok := byID[e]; ok {
			ia.Name = fmt.Sprint(r["entityid"])
			ia.Status = "active"
			if strings.EqualFold(fmt.Sprint(r["isinactive"]), "T") || r["isinactive"] == true {
				ia.Status = "inactive"
			}
		}
		inv.Agents = append(inv.Agents, ia)
	}
	return inv, nil
}

func entityIDs(s Settings) []string {
	var ids []string
	for _, e := range s.AgentMap {
		if digitsRe.MatchString(e) {
			ids = append(ids, e)
		}
	}
	sort.Strings(ids)
	return ids
}

func activityQuery(s Settings, cursor string, entities []string) (string, error) {
	if !digitsRe.MatchString(cursor) {
		return "", errors.New("netsuite: activity cursor must be numeric")
	}
	for _, e := range entities {
		if !digitsRe.MatchString(e) {
			return "", errors.New("netsuite: entity ids must be numeric")
		}
	}
	q := DefaultActivityQuery
	if strings.TrimSpace(s.ActivityQuery) != "" {
		q = s.ActivityQuery
	}
	if !strings.Contains(q, "{cursor}") || !strings.Contains(q, "{entities}") {
		return "", errors.New("netsuite: the activity query must contain {cursor} and {entities}")
	}
	return strings.ReplaceAll(strings.ReplaceAll(q, "{cursor}", cursor), "{entities}", strings.Join(entities, ",")), nil
}

// Activity implements saas.Connector: system notes after cursor (the last
// note id) made by mapped agents' entities. Every event is Observed: it
// happened before Fortik saw it.
func (c *Connector) Activity(ctx context.Context, cursor string) ([]saas.Activity, string, error) {
	s, err := c.settings(ctx)
	if err != nil {
		return nil, cursor, err
	}
	return c.activity(ctx, s, cursor)
}

// activity reads one tenant's system notes after cursor.
func (c *Connector) activity(ctx context.Context, s Settings, cursor string) ([]saas.Activity, string, error) {
	if cursor == "" {
		cursor = "0"
	}
	ids := entityIDs(s)
	if len(ids) == 0 {
		return nil, cursor, nil
	}
	agentOf := map[string]string{}
	for a, e := range s.AgentMap {
		agentOf[e] = a
	}
	q, err := activityQuery(s, cursor, ids)
	if err != nil {
		return nil, cursor, err
	}
	var out []saas.Activity
	next := cursor
	for page := 0; page < 10; page++ {
		rows, more, err := c.client.SuiteQL(ctx, s, q, 1000, page*1000)
		if err != nil {
			return out, next, err
		}
		for _, r := range rows {
			id := fmt.Sprint(r["id"])
			if !digitsRe.MatchString(id) {
				continue
			}
			ent := fmt.Sprint(r["name"])
			agent := agentOf[ent]
			ev := saas.Activity{NativeEventID: id, AgentNativeID: ent, Observed: true, Source: "netsuite system notes"}
			ev.At = parseNSDate(fmt.Sprint(r["date"]))
			ev.Action.AgentID = agent
			ev.Action.System = System
			ev.Action.Verb = "WRITE"
			ev.Action.Target = map[string]any{"operation": "observed_change", "integration_id": s.IntegrationID, "tenant": s.AccountID,
				"transport": integrations.TransportREST, "record_id": fmt.Sprint(r["recordid"]),
				"record_type_id": fmt.Sprint(r["recordtypeid"]), "field": clip(fmt.Sprint(r["field"]), 100),
				"context": clip(fmt.Sprint(r["context"]), 60), "netsuite_role": fmt.Sprint(r["role"]), "system_note_id": id}
			out = append(out, ev)
			if greater(id, next) {
				next = id
			}
		}
		if !more {
			break
		}
	}
	return out, next, nil
}

func greater(a, b string) bool {
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}

// parseNSDate accepts the date forms SuiteQL commonly returns; unknown forms
// yield the zero time (the recorder then uses the ingestion time and says so).
func parseNSDate(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "1/2/2006 3:04 pm", "1/2/2006 3:04 PM", "1/2/2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Contain implements saas.Connector. Fortik-side, every request through the
// gateway is refused by Decide once the agent is contained, and Fortik's
// cached token is dropped. NetSuite-side, no documented API to disable an
// entity's access or revoke its tokens was verified, so that part is
// "unknown": the result says what to do in NetSuite.
func (c *Connector) Contain(_ context.Context, agentNativeID, operation, _ string) (saas.ContainResult, error) {
	n := c.client.Drop()
	return saas.ContainResult{Operation: operation, Status: "unknown",
		Evidence: fmt.Sprintf("Fortik side: requests through the gateway are refused by Decide; %d cached NetSuite token(s) dropped", n),
		Residual: fmt.Sprintf("NOT revoked in NetSuite: entity %s's own logins, tokens and integrations are unaffected (no verified API); remove its role or revoke its client-credentials mapping in NetSuite", agentNativeID)}, nil
}

// Verify implements saas.Connector: there is no NetSuite-side state Fortik
// can re-read for a containment it could not apply.
func (c *Connector) Verify(_ context.Context, agentNativeID, operation string) (saas.ContainResult, error) {
	return saas.ContainResult{Operation: operation, Status: "unknown", Evidence: "no NetSuite-side containment to verify for entity " + agentNativeID}, nil
}

// Mint implements broker.Adapter: NetSuite credentials are never issued to
// agents (they use the gateway).
func (c *Connector) Mint(context.Context, string, map[string]any, time.Duration) (broker.Credential, error) {
	return broker.Credential{}, errors.New("netsuite: credentials are never issued to agents; call NetSuite through the Fortik gateway")
}

// RevokeAgent implements broker.Adapter (kill, suspend): honest semantics.
func (c *Connector) RevokeAgent(ctx context.Context, agentID string) (string, error) {
	ts, err := c.tenants(ctx)
	if err != nil {
		return "", err
	}
	if len(ts) == 0 {
		return "netsuite: integration not configured: nothing to revoke", nil
	}
	n := c.client.Drop()
	msg := fmt.Sprintf("netsuite: gateway requests refused by Decide; %d cached Fortik token(s) dropped (Fortik's token is not per agent)", n)
	for _, t := range ts {
		if ent := t.Settings.AgentMap[agentID]; ent != "" {
			msg += fmt.Sprintf("; %s: entity %s's own NetSuite access NOT revoked (no verified API): remove its role in NetSuite", t.Settings.IntegrationID, ent)
		}
	}
	return msg, nil
}

// Declaration implements saas.Connector (coverage).
func (c *Connector) Declaration() coverage.Declaration { return Declaration() }

// Declaration is NetSuite's coverage as of 2026-10-25: verified against a
// local fake only (no NetSuite account was available).
func Declaration() coverage.Declaration {
	fake := "internal/netsuite tests and scripts/demo-netsuite.sh against a LOCAL FAKE"
	acct := "connect a NetSuite sandbox (Integrations > NetSuite), run Test connection, then scripts/demo-netsuite.sh against it"
	cap := func(dim, status, ev, gap, fix string) coverage.Capability {
		return coverage.Capability{Dimension: dim, Status: status, Evidence: ev, Gap: gap, Fix: fix}
	}
	return coverage.Declaration{
		System: System, Title: "NetSuite REST API (SuiteTalk via the app gateway; system notes)", Integrations: []string{IntegrationKey, IntegrationKey + ":*"},
		Interception: "agents call NetSuite REST and SuiteQL through /gw/netsuite with Fortik's OAuth 2.0 client-credentials token; activity outside Fortik is read from system notes afterwards",
		Bypass:       "an agent with its own NetSuite login, token or integration (including NetSuite's own AI features) does not pass Fortik; such activity is only observed afterwards if its entity is mapped",
		Capabilities: []coverage.Capability{
			cap(coverage.DimDiscovery, coverage.Implemented, "", "no verified NetSuite API lists AI agents; mapped agents' entities are checked", acct),
			cap(coverage.DimIdentity, coverage.VerifiedTest, fake, "not verified against a real account", acct),
			cap(coverage.DimActivity, coverage.VerifiedTest, fake+" (system notes)", "audit data arrives after the change; column names verified only by Test connection on a real account", acct),
			cap(coverage.DimDelegation, coverage.VerifiedTest, "policy tests: delegation rules apply to netsuite actions through the gateway", "", ""),
			cap(coverage.DimPreExec, coverage.VerifiedTest, fake+" (gateway: holds, denies, snapshot-first updates)", "only for requests routed through Fortik", acct),
			cap(coverage.DimRevocation, coverage.Unsupported, "", "no verified API to revoke an entity's NetSuite tokens; Fortik drops its own token and refuses gateway calls", "revoke in NetSuite manually"),
			cap(coverage.DimSuspension, coverage.VerifiedTest, fake+" (Decide refuses a suspended agent's gateway calls)", "agents' direct NetSuite access is not suspended", acct),
			cap(coverage.DimUndo, coverage.VerifiedTest, fake+" (field snapshot restored by PATCH)", "last writer wins; creates, deletes and payments are not undoable (held instead)", acct),
			cap(coverage.DimEvidence, coverage.VerifiedLive, "Diary", "", ""),
		},
	}
}
