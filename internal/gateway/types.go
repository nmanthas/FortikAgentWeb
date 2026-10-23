// Package gateway is Fortik's app gateway for business apps (Google
// Workspace, GitHub). Agents call it with their Fortik agent token; each
// request is mapped to an Action, decided, narrowed and only then forwarded
// with a Fortik-held credential that never reaches the agent.
package gateway

import (
	"context"
	"net/http"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/decide"
)

// Op is an agent request mapped to Fortik's model.
type Op struct {
	Action action.Action // System, Verb, Target, PayloadSummary filled by the adapter
	// Body is the (possibly rewritten) request body to forward.
	Body []byte
	// State carries adapter-private data from Map to Forward (e.g. parsed MIME).
	State any
}

// Adapter handles one app under /gw/<prefix>/.
type Adapter interface {
	Prefix() string // "google" | "github"
	// Map turns the request into an Op. Unknown endpoints must return an Op
	// with Verb "UNKNOWN" (policy denies), never an error that bypasses Decide.
	Map(ctx context.Context, p authz.Principal, r *http.Request, body []byte) (Op, error)
	// Enrich runs pre-decision lookups (branch protection, internal domains...).
	Enrich(ctx context.Context, p authz.Principal, op *Op) error
	// Forward executes an allowed/allow_reduced Op. It MUST apply every key of
	// out.Result.ReducedForm it understands and refuse (return ErrReducedFormUnsupported)
	// if any key is unknown. It writes the upstream response to w.
	Forward(ctx context.Context, p authz.Principal, op *Op, out decide.Outcome, w http.ResponseWriter, r *http.Request) error
}

// ErrReducedFormUnsupported makes the gateway refuse (fail closed).
type ErrReducedFormUnsupported struct{ Key string }

func (e ErrReducedFormUnsupported) Error() string {
	return "reduced form key not supported by this adapter: " + e.Key
}
