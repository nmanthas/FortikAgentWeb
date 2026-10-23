# Shadow-agent rules (docs/PHASE5_DESIGN.md §3). A DISCOVERED agent was not
# registered by anyone: Fortik found its standing credential in a system it
# brokers (or saw it fail to authenticate) and registered it itself with no
# owner, at ISOLATED. The control ladder already confines it (POL-012); these
# rules hold even if its level is raised before it is registered properly
# with an owner (POST /v1/shadow/{id}/register):
#
#   POL-680 an unowned discovered agent never reaches outside the company
#           (external egress, any verb)
#   POL-681 an unowned discovered agent never changes permissions (GRANT)
#   POL-682 an unowned discovered agent never spawns or calls other agents
#           (DELEGATE)
#   POL-683 an unowned discovered agent never sends, exports or spends
#   POL-684 a discovered agent whose shadow finding is still open or flagged
#           for revocation may only READ (input.context.shadow.flagged,
#           supplied by the shadow enricher)
#   POL-689 malformed input.context.shadow: fail closed
#
# Every rule is a deny gate (fortik.gates), never approvable.
package fortik.shadow

agent := object.get(input, "agent", {})

act := input.action

tgt := object.get(act, "target", {})

verb := object.get(act, "verb", "")

discovered if agent.discovered == true

has_owner if {
	s := object.get(agent, "sponsor", "")
	is_string(s)
	trim_space(s) != ""
}

unowned if {
	discovered
	not has_owner
}

external if tgt.external == true

external if {
	n := object.get(tgt, "external_domains", 0)
	is_number(n)
	n > 0
}

context_obj := object.get(input, "context", {})

has_ctx if {
	is_object(context_obj)
	"shadow" in object.keys(context_obj)
}

ctx := context_obj.shadow if has_ctx

well_formed if {
	is_object(ctx)
	is_boolean(object.get(ctx, "flagged", false))
}

aid := object.get(agent, "agent_id", "")

denials contains {"rule_id": "POL-680", "reason": sprintf("discovered agent %v has no owner: external egress refused until it is registered with an owner", [aid])} if {
	unowned
	external
}

denials contains {"rule_id": "POL-681", "reason": sprintf("discovered agent %v has no owner: permission changes (GRANT) refused", [aid])} if {
	unowned
	verb == "GRANT"
}

denials contains {"rule_id": "POL-682", "reason": sprintf("discovered agent %v has no owner: it may not spawn or call other agents (DELEGATE)", [aid])} if {
	unowned
	verb == "DELEGATE"
}

denials contains {"rule_id": "POL-683", "reason": sprintf("discovered agent %v has no owner: %v refused", [aid, verb])} if {
	unowned
	verb in {"SEND", "EXPORT", "SPEND"}
}

denials contains {"rule_id": "POL-684", "reason": sprintf("discovered agent %v: its credential is flagged for revocation; only READ until the finding is revoked, dismissed or registered (%v refused)", [aid, verb])} if {
	well_formed
	ctx.flagged == true
	verb != "READ"
}

denials contains {"rule_id": "POL-689", "reason": "malformed shadow context: fail closed"} if {
	has_ctx
	not well_formed
}
