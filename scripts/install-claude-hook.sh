#!/usr/bin/env bash
# Install (or remove) Fortik's Claude Code PreToolUse hook
# (docs/PHASE3_DESIGN.md §3.2). The hook lets Fortik refuse risky tool calls
# before a coding agent runs them; it never grants permissions itself.
#
#   scripts/install-claude-hook.sh [--user] [--uninstall] [--fortik PATH] [--dry-run]
#
#   --user       write ~/.claude/settings.json (default: managed settings,
#                /Library/Application Support/ClaudeCode/managed-settings.json
#                on macOS, /etc/claude-code/managed-settings.json on Linux,
#                with allowManagedHooksOnly: true)
#   --uninstall  remove Fortik's hook entry (other hooks are kept)
#   --fortik     path of the fortik binary (default: `command -v fortik`)
#   --dry-run    print the resulting settings without writing
#
# The previous file is backed up as <file>.bak.<timestamp>. The script never
# changes permission settings (no bypass modes, no allow rules).
set -euo pipefail

scope=managed
action=install
dry=0
fortik_bin=""

while [ $# -gt 0 ]; do
	case "$1" in
	--user) scope=user ;;
	--managed) scope=managed ;;
	--uninstall) action=uninstall ;;
	--dry-run) dry=1 ;;
	--fortik)
		shift
		fortik_bin="${1:?--fortik needs a path}"
		;;
	-h | --help)
		sed -n '2,19p' "$0"
		exit 0
		;;
	*)
		echo "unknown option: $1" >&2
		exit 64
		;;
	esac
	shift
done

command -v python3 >/dev/null 2>&1 || {
	echo "python3 is required" >&2
	exit 69
}

if [ "$scope" = user ]; then
	settings="${HOME:?}/.claude/settings.json"
else
	case "$(uname -s)" in
	Darwin) settings="/Library/Application Support/ClaudeCode/managed-settings.json" ;;
	Linux) settings="/etc/claude-code/managed-settings.json" ;;
	*)
		echo "managed settings are not supported on $(uname -s); use --user" >&2
		exit 69
		;;
	esac
fi

if [ "$action" = install ]; then
	if [ -z "$fortik_bin" ]; then
		fortik_bin="$(command -v fortik || true)"
	fi
	if [ -z "$fortik_bin" ] || [ ! -x "$fortik_bin" ]; then
		echo "fortik binary not found; pass --fortik /path/to/fortik" >&2
		exit 69
	fi
	case "$fortik_bin" in
	/*) ;;
	*) fortik_bin="$(cd "$(dirname "$fortik_bin")" && pwd)/$(basename "$fortik_bin")" ;;
	esac
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 -I - "$settings" "$action" "$scope" "${fortik_bin:-}" "$tmp" <<'PY'
import json, os, shlex, sys

path, action, scope, fortik, out = sys.argv[1:6]
data = {}
if os.path.exists(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if text.strip():
        data = json.loads(text)
if not isinstance(data, dict):
    sys.exit("settings file is not a JSON object: " + path)

MARK = "hook claude-code"

def is_fortik(h):
    return isinstance(h, dict) and MARK in str(h.get("command", ""))

hooks = data.setdefault("hooks", {})
if not isinstance(hooks, dict):
    sys.exit("settings.hooks is not an object")
pre = hooks.get("PreToolUse", [])
if not isinstance(pre, list):
    sys.exit("settings.hooks.PreToolUse is not a list")

changes = []
kept = []
for group in pre:
    if isinstance(group, dict) and isinstance(group.get("hooks"), list):
        inner = [h for h in group["hooks"] if not is_fortik(h)]
        if len(inner) != len(group["hooks"]):
            changes.append("removed existing Fortik hook (matcher %r)" % group.get("matcher"))
        if inner:
            kept.append(dict(group, hooks=inner))
    else:
        kept.append(group)

if action == "install":
    cmd = shlex.quote(fortik) + " " + MARK
    kept.append({"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 30}]})
    changes.append("added PreToolUse hook (matcher \"*\", timeout 30s): " + cmd)
    if scope == "managed" and data.get("allowManagedHooksOnly") is not True:
        data["allowManagedHooksOnly"] = True
        changes.append("set allowManagedHooksOnly: true")

if kept:
    hooks["PreToolUse"] = kept
else:
    hooks.pop("PreToolUse", None)
if not hooks:
    data.pop("hooks", None)

with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
for c in changes or ["no changes"]:
    print("  - " + c)
PY

echo "settings: $settings"
if [ "$dry" = 1 ]; then
	cat "$tmp"
	exit 0
fi

mkdir -p "$(dirname "$settings")"
if [ -f "$settings" ]; then
	backup="$settings.bak.$(date +%Y%m%d%H%M%S).$$"
	cp -p "$settings" "$backup"
	echo "backup:   $backup"
fi
cp "$tmp" "$settings"
chmod 0644 "$settings"
echo "done. Set FORTIK_GATEWAY_URL and FORTIK_AGENT_TOKEN (or FORTIK_AGENT_TOKEN_FILE) in the agent's environment."
