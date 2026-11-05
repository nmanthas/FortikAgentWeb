# Timed app suspensions (docs/PHASE3_DESIGN.md §5). The overrides enricher
# supplies input.context.overrides = {"active": [Override...]}: every override
# in force (status active or blocked) for the acting agent, directly or via
# its team, on the action's system. This package adds deny gates:
#
#   POL-030 mode suspended: no access to the system
#   POL-031 mode read_only and the verb is not a read
#
# Fail closed: an unknown or missing mode counts as suspended; a blocked
# override (automatic restore refused) is enforced until released; a
# malformed timestamp makes evaluation error, which Decide fails closed on.
package fortik.overrides

# Read through the exact path (never all of data.fortik, which would pull in
# every package and recurse).
cfg := c if {
	c := data.fortik.overrides.config
	is_object(c)
} else := {}

act := input.action

ctx := object.get(object.get(input, "context", {}), "overrides", {})

raw_active := v if {
	v := ctx.active
	is_array(v)
} else := []

in_force contains o if {
	some o in raw_active
	is_object(o)
	object.get(o, "status", "") in {"active", "blocked"}
	override_covers(object.get(o, "system", ""))
}

override_covers(sys) if sys == act.system

# A copilot connector's token reaches its upstream's systems (Phase 6): a
# timed suspension of gmail, drive or github stops it too.
override_covers(sys) if {
	act.system == "connector"
	ups := object.get(object.get(act, "target", {}), "upstream_systems", [])
	is_array(ups)
	sys in ups
}

# A shell command that reaches GitHub (gh, git push/fetch/clone) or AWS (the
# aws CLI) is covered by that system's suspensions. Only ever stricter.
override_covers(sys) if {
	reaches := object.get(object.get(act, "target", {}), "reaches", [])
	is_array(reaches)
	sys in reaches
}

read_only(o) if o.mode == "read_only"

suspensions := {o | some o in in_force; not read_only(o)}

read_onlys := {o | some o in in_force; read_only(o)}

open_ended(o) if not o.expires_at

open_ended(o) if o.expires_at == null

open_ended(o) if o.status == "blocked"

# Sort key: open-ended first, then the latest restore time, then id.
rank(o) := [0, 0, object.get(o, "override_id", "")] if {
	open_ended(o)
} else := [1, 0 - time.parse_rfc3339_ns(o.expires_at), object.get(o, "override_id", "")]

# The most restrictive override of a set (deterministic).
winner(set) := sorted[0][1] if {
	sorted := sort([[rank(o), o] | some o in set])
	count(sorted) > 0
}

layout := object.get(cfg, "time_layout", "15:04 MST on 2006-01-02")

zone := object.get(cfg, "time_zone", "UTC")

when(o) := sprintf("until released (automatic restore was blocked: %v)", [object.get(o, "blocked_reason", "")]) if {
	o.status == "blocked"
} else := "until released" if {
	open_ended(o)
} else := sprintf("until %s", [time.format([time.parse_rfc3339_ns(o.expires_at), zone, layout])])

describe(o) := sprintf("by %v: %v [override %v]", [
	object.get(o, "created_by", "unknown"),
	object.get(o, "reason", ""),
	object.get(o, "override_id", ""),
])

read_verbs := {v | some v in object.get(cfg, "read_only_verbs", ["READ"])}
