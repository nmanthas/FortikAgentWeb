# Access-profile gate (Phase 2, docs/PHASE2_DESIGN.md §5). Decide passes the
# agent's current profile for the action's system as input.access:
#   {"system": "<system>", "version": N, "profile": {...}}   or
#   {"system": "<system>", "version": 0, "profile": null}     (no profile)
#
# The gate applies only when input.access is present and the action's system
# is one that has profiles. It denies outright (not approvable, no ladder
# change of its own); fortik.decide checks it after the control gate.
# Anything missing or malformed in the profile grants nothing (fail closed).
#
#   POL-020 no profile, or mode / send / the upstream is none
#   POL-021 mode read_only and the verb is not READ (drive, aws)
#   POL-022 gmail send internal_only and the message is external
#   POL-023 drive share internal_only and the share is external or anyone;
#           share none and the action is a share
#   POL-024 github repo not in repos, or a needed permission is missing
#   POL-025 aws service not in services, or the action matches denied_actions
#   POL-026 postgres upstream not in the profile, or read_only and not READ
#   POL-027 recipients exceed max_recipients
#   POL-028 http external egress outside the profile (Phase 3)
#   POL-029 mcp server or tool not in the profile (Phase 3)
#
# Phase 3 systems (docs/PHASE3_DESIGN.md §1.5): a2a, http and mcp. No
# profile denies (POL-020) like every other profiled system. The a2a
# delegation targets and depth are checked by fortik.delegation (POL-603);
# here an a2a profile only has to exist. http without a profile is the
# exception: see the POL-020 rule below. A DELEGATE to the acting agent
# itself (a Claude Code Task subagent) is exempt: it grants nothing new.
package fortik.access

profiled_systems := {"gmail", "drive", "github", "aws", "postgres", "a2a", "http", "mcp"}

act := input.action

tgt := object.get(act, "target", {})

verb := object.get(act, "verb", "")

recipients := object.get(object.get(act, "payload_summary", {}), "recipients", 0)

applies if {
	input.access
	act.system in profiled_systems
	not self_delegation
}

self_delegation if {
	act.system == "a2a"
	verb == "DELEGATE"
	is_string(tgt.to_agent)
	tgt.to_agent != ""
	tgt.to_agent == act.agent_id
}

profile := input.access.profile if is_object(input.access.profile)

version := object.get(input.access, "version", 0)

prefix := sprintf("access profile v%v for %s", [version, act.system])

# Profile values are read through these helpers so a missing or mistyped
# field never grants anything.
pstr(key) := v if {
	v := profile[key]
	is_string(v)
} else := ""

plist(key) := v if {
	v := profile[key]
	is_array(v)
} else := []

pobj(key) := v if {
	v := profile[key]
	is_object(v)
} else := {}

external if tgt.external == true

external if {
	n := object.get(tgt, "external_domains", 0)
	is_number(n)
	n > 0
}

# Malformed external markers count as external (POL-009 denies them anyway).
external if {
	v := object.get(tgt, "external", false)
	not is_boolean(v)
}

external if {
	v := object.get(tgt, "external_domains", 0)
	not is_number(v)
}

# --- POL-020: no profile at all, or the input is inconsistent -------------

denials contains {"rule_id": "POL-020", "reason": sprintf("no access profile for %s: access denied by default", [act.system])} if {
	not profile
	not http_open_default
}

# The default applies to the acting agent only. When fortik.delegation
# re-checks an originating hop (input.agent swapped for the hop), a hop
# without an http profile still refuses: a delegated fetch must be within
# the originator's explicit permissions (UC1).
http_open_default if {
	act.system == "http"
	object.get(object.get(input, "agent", {}), "agent_id", "") == act.agent_id
}

# http without a profile is not denied here: external browsing (READ) is
# restricted only once an http profile exists (POL-028); uploads without a
# profile are held by POL-505 (fortik.rules, http.rego) and other verbs by
# POL-005. A profile, once present, is enforced in full below.

denials contains {"rule_id": "POL-020", "reason": sprintf("access profile is for %v, not %s: denied", [object.get(input.access, "system", "(none)"), act.system])} if {
	profile
	object.get(input.access, "system", "") != act.system
}

# --- Gmail ------------------------------------------------------------------

gmail_send_ok := {"internal_only", "any"}

denials contains {"rule_id": "POL-020", "reason": sprintf("%s: send is %v: no sending or mailbox changes", [prefix, pstr("send")])} if {
	act.system == "gmail"
	profile
	verb != "READ"
	not pstr("send") in gmail_send_ok
}

denials contains {"rule_id": "POL-020", "reason": sprintf("%s: read is not granted", [prefix])} if {
	act.system == "gmail"
	profile
	verb == "READ"
	not profile.read == true
}

denials contains {"rule_id": "POL-022", "reason": sprintf("%s: send is internal_only and this message has external recipients", [prefix])} if {
	act.system == "gmail"
	profile
	verb != "READ"
	pstr("send") == "internal_only"
	external
}

max_recipients := v if {
	v := profile.max_recipients
	is_number(v)
} else := 0

denials contains {"rule_id": "POL-027", "reason": sprintf("%s: %v recipients exceed max_recipients %v", [prefix, recipients, max_recipients])} if {
	act.system == "gmail"
	profile
	verb != "READ"
	is_number(recipients)
	recipients > max_recipients
}

denials contains {"rule_id": "POL-027", "reason": sprintf("%s: malformed recipient count", [prefix])} if {
	act.system == "gmail"
	profile
	not is_number(recipients)
}

# --- Drive and AWS: mode -----------------------------------------------------

modes_ok := {"read_only", "read_write"}

denials contains {"rule_id": "POL-020", "reason": sprintf("%s: mode is %v: no access", [prefix, pstr("mode")])} if {
	act.system in {"drive", "aws"}
	profile
	not pstr("mode") in modes_ok
}

denials contains {"rule_id": "POL-021", "reason": sprintf("%s: mode is read_only: %v refused", [prefix, verb])} if {
	act.system in {"drive", "aws"}
	profile
	pstr("mode") == "read_only"
	verb != "READ"
}

# --- Drive: sharing ----------------------------------------------------------

drive_share if lower(object.get(tgt, "operation", "")) == "share"

share_type := lower(object.get(tgt, "share_type", ""))

denials contains {"rule_id": "POL-023", "reason": sprintf("%s: share is %v: sharing refused", [prefix, pstr("share")])} if {
	act.system == "drive"
	profile
	drive_share
	not pstr("share") in {"internal_only", "any"}
}

denials contains {"rule_id": "POL-023", "reason": sprintf("%s: share is internal_only: external or public share refused", [prefix])} if {
	act.system == "drive"
	profile
	drive_share
	pstr("share") == "internal_only"
	drive_share_outside
}

drive_share_outside if external

drive_share_outside if share_type == "anyone"

# --- GitHub ------------------------------------------------------------------

gh_repos := {lower(r) | some r in plist("repos"); is_string(r)}

gh_perms := pobj("permissions")

gh_op := lower(object.get(tgt, "operation", ""))

credential_request if tgt.credential_request == true

# Repositories the action touches: target.repo (gateway) or target.repos
# (direct credential request).
gh_target_repos := {lower(r) | some r in object.get(tgt, "repos", []); is_string(r)} if credential_request

else := {lower(r) | r := object.get(tgt, "repo", ""); is_string(r); r != ""}

denials contains {"rule_id": "POL-024", "reason": sprintf("%s: the request names no repository", [prefix])} if {
	act.system == "github"
	profile
	count(gh_target_repos) == 0
}

denials contains {"rule_id": "POL-024", "reason": sprintf("%s: repository %s is not in the profile", [prefix, r])} if {
	act.system == "github"
	profile
	some r in gh_target_repos
	not r in gh_repos
}

gh_contents_ops := {"push", "force_push", "delete_branch", "merge_pr", "create_branch", "update_ref", "edit_workflow"}

gh_pr_ops := {"create_pr", "close_pr", "merge_pr", "update_pr", "reopen_pr"}

gh_issue_ops := {"create_issue", "update_issue", "close_issue", "comment_issue"}

gh_known_write_ops := ((gh_contents_ops | gh_pr_ops) | gh_issue_ops) | {"comment"}

# Permissions the operation needs at write level.
gh_needs contains "contents" if gh_op in gh_contents_ops

# Writing file contents (target.paths) always needs contents:write.
gh_needs contains "contents" if {
	verb != "READ"
	count(object.get(tgt, "paths", [])) > 0
}

# Comments: on a pull request they need pull_requests:write, on an issue
# issues:write (the gateway's templated endpoint says which).
gh_comment_on_pr if contains(lower(object.get(tgt, "endpoint", "")), "/pulls/")

gh_needs contains "pull_requests" if {
	gh_op == "comment"
	gh_comment_on_pr
}

gh_needs contains "issues" if {
	gh_op == "comment"
	not gh_comment_on_pr
}

gh_needs contains "pull_requests" if gh_op in gh_pr_ops

gh_needs contains "issues" if gh_op in gh_issue_ops

# An unmapped mutating operation needs the strongest common permission.
gh_needs contains "contents" if {
	not credential_request
	verb != "READ"
	not gh_op in gh_known_write_ops
}

denials contains {"rule_id": "POL-024", "reason": sprintf("%s: %v needs %s:write", [prefix, gh_op, p])} if {
	act.system == "github"
	profile
	not credential_request
	some p in gh_needs
	object.get(gh_perms, p, "") != "write"
}

# Direct credential requests: allowed only with allow_direct_token, and each
# requested permission must be within the profile (read <= write).
perm_rank := {"read": 1, "write": 2}

denials contains {"rule_id": "POL-024", "reason": sprintf("%s: direct tokens are not allowed (allow_direct_token is false)", [prefix])} if {
	act.system == "github"
	profile
	credential_request
	not profile.allow_direct_token == true
}

denials contains {"rule_id": "POL-024", "reason": sprintf("%s: permission %v:%v exceeds the profile (%v)", [prefix, k, v, object.get(gh_perms, k, "none")])} if {
	act.system == "github"
	profile
	credential_request
	some k, v in object.get(tgt, "permissions", {})
	not gh_within(k, v)
}

denials contains {"rule_id": "POL-024", "reason": sprintf("%s: the request names no permissions", [prefix])} if {
	act.system == "github"
	profile
	credential_request
	count(object.get(tgt, "permissions", {})) == 0
}

gh_within(k, v) if perm_rank[v] <= perm_rank[gh_perms[k]]

# --- AWS: services and denied actions ---------------------------------------

aws_action := lower(object.get(tgt, "iam_action", ""))

aws_parts := split(aws_action, ":")

aws_service := aws_parts[0] if {
	count(aws_parts) == 2
	aws_parts[0] != ""
	aws_parts[1] != ""
}

denials contains {"rule_id": "POL-025", "reason": sprintf("%s: malformed or missing iam_action %v", [prefix, object.get(tgt, "iam_action", "")])} if {
	act.system == "aws"
	profile
	not aws_service
}

denials contains {"rule_id": "POL-025", "reason": sprintf("%s: service %s is not in the profile", [prefix, aws_service])} if {
	act.system == "aws"
	profile
	not aws_service in {lower(s) | some s in plist("services"); is_string(s)}
}

denials contains {"rule_id": "POL-025", "reason": sprintf("%s: %s matches denied action %s", [prefix, aws_action, pat])} if {
	act.system == "aws"
	profile
	some pat in plist("denied_actions")
	is_string(pat)
	glob.match(lower(pat), null, aws_action)
}

# --- Postgres: per-upstream mode --------------------------------------------

pg_upstream := u if {
	u := tgt.upstream
	is_string(u)
	u != ""
}

pg_mode := m if {
	m := pobj("upstreams")[pg_upstream]
	is_string(m)
}

denials contains {"rule_id": "POL-026", "reason": sprintf("%s: the statement names no upstream", [prefix])} if {
	act.system == "postgres"
	profile
	not pg_upstream
}

denials contains {"rule_id": "POL-026", "reason": sprintf("%s: upstream %s is not in the profile", [prefix, pg_upstream])} if {
	act.system == "postgres"
	profile
	not pg_mode
}

denials contains {"rule_id": "POL-020", "reason": sprintf("%s: upstream %s is %v: no access", [prefix, pg_upstream, pg_mode])} if {
	act.system == "postgres"
	profile
	m := pg_mode
	not m in modes_ok
}

denials contains {"rule_id": "POL-026", "reason": sprintf("%s: upstream %s is read_only: %v refused", [prefix, pg_upstream, verb])} if {
	act.system == "postgres"
	profile
	pg_mode == "read_only"
	verb != "READ"
}

# --- HTTP: external egress (POL-028) ------------------------------------------

# Only an explicit external: false is internal; a missing or malformed marker
# counts as external (fail closed).
http_external if not tgt.external == false

http_host := h if {
	d := tgt.domain
	is_string(d)
	h := trim_suffix(lower(split(trim_space(d), ":")[0]), ".")
	h != ""
}

# allowed_domains entries are normalised (lowercase, no trailing dot) by
# profile validation; "*.example.org" covers subdomains at any depth.
http_domain_allowed if {
	some p in plist("allowed_domains")
	is_string(p)
	p == http_host
}

http_domain_allowed if {
	some p in plist("allowed_domains")
	is_string(p)
	startswith(p, "*.")
	endswith(http_host, substring(p, 1, -1))
}

denials contains {"rule_id": "POL-028", "reason": sprintf("%s: external is %v: external egress refused", [prefix, pstr("external")])} if {
	act.system == "http"
	profile
	http_external
	not pstr("external") in {"allowlist", "any"}
}

denials contains {"rule_id": "POL-028", "reason": sprintf("%s: the external request names no domain", [prefix])} if {
	act.system == "http"
	profile
	http_external
	pstr("external") == "allowlist"
	not http_host
}

denials contains {"rule_id": "POL-028", "reason": sprintf("%s: domain %s is not in allowed_domains", [prefix, http_host])} if {
	act.system == "http"
	profile
	http_external
	pstr("external") == "allowlist"
	not http_domain_allowed
}

# --- MCP: servers and tools (POL-029) -------------------------------------------

mcp_server := s if {
	s := tgt.server
	is_string(s)
	s != ""
}

mcp_tools := t if {
	t := pobj("servers")[mcp_server]
	is_array(t)
}

# A tool call names its tool; list/read requests carry no tool (or "").
mcp_tool_named if {
	t := object.get(tgt, "tool", "")
	t != ""
}

denials contains {"rule_id": "POL-029", "reason": sprintf("%s: the request names no MCP server", [prefix])} if {
	act.system == "mcp"
	profile
	not mcp_server
}

denials contains {"rule_id": "POL-029", "reason": sprintf("%s: MCP server %s is not in the profile", [prefix, mcp_server])} if {
	act.system == "mcp"
	profile
	not mcp_tools
}

denials contains {"rule_id": "POL-029", "reason": sprintf("%s: malformed MCP tool name", [prefix])} if {
	act.system == "mcp"
	profile
	mcp_tool_named
	not is_string(tgt.tool)
}

denials contains {"rule_id": "POL-029", "reason": sprintf("%s: tool %v is not allowed on MCP server %s", [prefix, tgt.tool, mcp_server])} if {
	act.system == "mcp"
	profile
	mcp_tool_named
	is_string(tgt.tool)
	tools := mcp_tools
	not "*" in tools
	not tgt.tool in tools
}

# --- gate ------------------------------------------------------------------

# The deciding denial: lowest rule id (then reason), so the pick is deterministic.
ranked := sort([[d.rule_id, d.reason] | some d in denials])

gate := {"rule_id": ranked[0][0], "reason": ranked[0][1]} if {
	applies
	count(ranked) > 0
}
