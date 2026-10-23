package commap

import (
	"context"

	"fortik/internal/action"
	"fortik/internal/control"
)

// EnricherKey is the input.context key POL-671 reads its threshold from.
const EnricherKey = "hidden"

// Enricher supplies input.context.hidden = {"encoded_param_min": N} (from
// map.encoded_param_min) to actions that carry a URL, a query string or an
// adapter's encoded_params summary, so POL-671 and the map use the same
// configured threshold. Other actions get nothing (the
// context is stored with every decision; it stays small). Without the
// enricher the policy uses data.fortik.hidden.encoded_param_min.
type Enricher struct{ min int }

// NewEnricher returns the decide.Enricher (wire it in svc.Enrichers).
func NewEnricher(encodedParamMin int) *Enricher {
	return &Enricher{min: max(encodedParamMin, EncodedParamFloor)}
}

func (e *Enricher) Key() string { return EnricherKey }

func (e *Enricher) Enrich(_ context.Context, a action.Action, _ control.State) (any, error) {
	_, hasURL := a.Target["url"].(string)
	_, hasQuery := a.Target["query"].(string)
	_, hasSummary := a.Target["encoded_params"]
	if !hasURL && !hasQuery && !hasSummary {
		return nil, nil
	}
	return map[string]any{"encoded_param_min": e.min}, nil
}
