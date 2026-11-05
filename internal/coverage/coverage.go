// Package coverage reports, per integration, what Fortik can actually do and
// what has actually been verified: prevented before execution (A), detected
// and contained after execution (B), observed only (C), or not verified /
// unknown (D). Each capability dimension is reported separately so that a
// strong dimension never hides a missing one, and every gap says its cause
// and how to close it. There is deliberately no single overall score.
//
// The capability statuses are declarations backed by named evidence (tests,
// demo scripts). They are combined at request time with whether the
// integration is actually connected in this deployment: an integration that
// is not connected is class D whatever its code can do.
package coverage

import (
	"context"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Status of one capability dimension.
const (
	VerifiedLive  = "verified_live"  // exercised end to end against the real system in this environment
	VerifiedTest  = "verified_test"  // exercised by automated tests against local fakes or test servers only
	Implemented   = "implemented"    // code exists; not verified end to end
	Unsupported   = "unsupported"    // the platform offers no such control, or it does not apply
	NotBuilt      = "not_built"      // planned; no code yet
	NotConfigured = "not_configured" // code exists but the integration is not connected here
)

// Dimension names.
const (
	DimDiscovery   = "discovery"
	DimIdentity    = "identity_attribution"
	DimActivity    = "activity_visibility"
	DimDelegation  = "delegation_visibility"
	DimPreExec     = "pre_execution_enforcement"
	DimRevocation  = "credential_revocation"
	DimSuspension  = "suspension"
	DimUndo        = "undo"
	DimEvidence    = "evidence_integrity"
	dimCount       = 9
	ClassPrevented = "A"
	ClassContained = "B"
	ClassObserved  = "C"
	ClassUnknown   = "D"
)

// Dimensions in display order.
var Dimensions = []string{DimDiscovery, DimIdentity, DimActivity, DimDelegation, DimPreExec, DimRevocation, DimSuspension, DimUndo, DimEvidence}

// Capability is one dimension of one integration.
type Capability struct {
	Dimension string `json:"dimension"`
	Status    string `json:"status"`
	Evidence  string `json:"evidence,omitempty"` // test or demo that verifies it
	Gap       string `json:"gap,omitempty"`      // what is missing and why
	Fix       string `json:"fix,omitempty"`      // how to improve coverage
}

// Declaration is what an integration's code can do (static).
type Declaration struct {
	System       string       `json:"system"`
	Title        string       `json:"title"`
	Interception string       `json:"interception"`               // how actions reach Fortik
	Integrations []string     `json:"integration_keys,omitempty"` // integration keys that connect it ("postgres:*" = any)
	BuiltIn      bool         `json:"built_in"`                   // needs no integration (e.g. the hook)
	Bypass       string       `json:"bypass,omitempty"`           // known routes around the enforcement point
	Capabilities []Capability `json:"capabilities"`
	Milestone    string       `json:"milestone,omitempty"` // for not-yet-built integrations
}

// Report is a declaration combined with this deployment's connection state.
type Report struct {
	Declaration
	Connected  bool   `json:"connected"`
	Connection string `json:"connection"` // e.g. "postgres:acme_prod ok", "not connected"
	Class      string `json:"class"`
	ClassLabel string `json:"class_label"`
	ClassWhy   string `json:"class_why"`
}

var classLabels = map[string]string{
	ClassPrevented: "Prevented before execution",
	ClassContained: "Detected and contained after execution",
	ClassObserved:  "Observed only",
	ClassUnknown:   "Not verified or unknown",
}

func (d Declaration) status(dim string) string {
	for _, c := range d.Capabilities {
		if c.Dimension == dim {
			return c.Status
		}
	}
	return NotBuilt
}

// Classify: A needs verified-live pre-execution enforcement on a connected
// integration; B verified-live revocation or suspension; C verified-live
// activity visibility; anything else is D. Test-only verification never
// earns A, B or C: it is not proof on the customer's real system.
func Classify(d Declaration, connected bool) (string, string) {
	if !connected {
		return ClassUnknown, "not connected in this deployment"
	}
	switch {
	case d.status(DimPreExec) == VerifiedLive:
		return ClassPrevented, "pre-execution enforcement verified live on this path"
	case d.status(DimRevocation) == VerifiedLive || d.status(DimSuspension) == VerifiedLive:
		return ClassContained, "containment verified live; no verified pre-execution enforcement"
	case d.status(DimActivity) == VerifiedLive:
		return ClassObserved, "activity visible; no verified enforcement or containment"
	default:
		return ClassUnknown, "no capability verified against the real system yet"
	}
}

// Service builds reports.
type Service struct {
	pool  *pgxpool.Pool
	decls []Declaration
	// BuiltInOn reports whether a built-in path is enabled (e.g. agentgw).
	BuiltInOn func(system string) bool
}

// New returns the coverage service over the given declarations.
func New(pool *pgxpool.Pool, decls []Declaration, builtInOn func(string) bool) *Service {
	return &Service{pool: pool, decls: decls, BuiltInOn: builtInOn}
}

// Reports combines every declaration with the current integration state.
func (s *Service) Reports(ctx context.Context) ([]Report, error) {
	status := map[string]string{}
	rows, err := s.pool.Query(ctx, `SELECT key, status FROM integrations`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, st string
		if err := rows.Scan(&k, &st); err != nil {
			rows.Close()
			return nil, err
		}
		status[k] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Report, 0, len(s.decls))
	for _, d := range s.decls {
		r := Report{Declaration: d}
		switch {
		case d.Milestone != "":
			r.Connection = "not built (" + d.Milestone + ")"
		case d.BuiltIn:
			r.Connected = s.BuiltInOn == nil || s.BuiltInOn(d.System)
			r.Connection = map[bool]string{true: "built in, enabled", false: "built in, disabled in the config"}[r.Connected]
		default:
			var parts []string
			for _, want := range d.Integrations {
				for k, st := range status {
					if k == want || (strings.HasSuffix(want, ":*") && strings.HasPrefix(k, strings.TrimSuffix(want, "*"))) {
						parts = append(parts, k+" "+st)
						if st == "ok" || st == "configured" {
							r.Connected = true
						}
					}
				}
			}
			if len(parts) == 0 {
				r.Connection = "not connected (console > Integrations)"
			} else {
				r.Connection = strings.Join(parts, ", ")
			}
		}
		if !r.Connected {
			// Code that cannot run here is not coverage here.
			caps := make([]Capability, len(d.Capabilities))
			copy(caps, d.Capabilities)
			for i := range caps {
				if caps[i].Status == VerifiedLive || caps[i].Status == VerifiedTest || caps[i].Status == Implemented {
					if caps[i].Gap == "" {
						caps[i].Gap = "integration not connected in this deployment"
					}
				}
			}
			r.Capabilities = caps
		}
		r.Class, r.ClassWhy = Classify(d, r.Connected)
		r.ClassLabel = classLabels[r.Class]
		out = append(out, r)
	}
	return out, nil
}

// Register mounts GET /v1/coverage (auditor or security).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/coverage", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
			return
		}
		rs, err := s.Reports(r.Context())
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "coverage: could not read integration state")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"integrations": rs, "dimensions": Dimensions, "classes": classLabels,
			"note": "Each dimension is reported separately; there is no overall score. Class A/B/C requires verification against the real system (verified_live)."})
	})
}
