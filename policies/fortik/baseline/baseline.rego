# Baselines (docs/PHASE5_DESIGN.md §4): the agent's own hourly volume per
# verb, computed by internal/baseline and supplied as input.context.baseline:
#   {current, mean, stddev, median, history_days, threshold, above_normal,
#    method, min_count}
# `current` includes the call being decided. The Go enricher applies the
# statistics (mean + sigma x stddev, or median_factor x median with less than
# min_history_days of history, never below min_count, never for an agent
# without history); policy reads its verdict.
package fortik.baseline

ctx := input.context.baseline

present if {
	_ = ctx
}

# The enricher's verdict, only when well formed.
well_formed if {
	is_object(ctx)
	is_boolean(ctx.above_normal)
	is_number(ctx.current)
	is_number(ctx.threshold)
}

above_normal if {
	well_formed
	ctx.above_normal == true
}

# A baseline context that is present but malformed fails closed (POL-661).
malformed if {
	present
	not well_formed
}
