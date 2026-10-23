# HTTP rules (docs/PHASE3_DESIGN.md §3.4) for system "http" (Claude Code
# WebFetch/WebSearch, agentgateway HTTP egress). External READ is allowed by
# default; once the agent has an http access profile, fortik.access enforces
# it (POL-028). Uploads (SEND/EXPORT/WRITE) need a human (POL-505); sensitive
# data leaving is red via POL-003. Other non-READ verbs are POL-005.
package fortik.rules

findings contains {
	"rule_id": "POL-505",
	"class": "yellow",
	"reason": sprintf("http %s to %v: upload needs approval", [act.verb, object.get(tgt, "domain", "")]),
	"hold": true,
} if {
	act.system == "http"
	act.verb in {"SEND", "EXPORT", "WRITE"}
}
