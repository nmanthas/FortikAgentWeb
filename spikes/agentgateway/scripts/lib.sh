# Shared helpers for the spike scripts. Source from the spike root.
# shellcheck shell=bash
OUT=${OUT:-out}
mkdir -p "$OUT"

wait_port() { # host:port
  for _ in $(seq 100); do nc -z "${1%:*}" "${1#*:}" 2>/dev/null && return 0; sleep 0.1; done
  echo "timeout waiting for $1" >&2; return 1
}

stop_pid() { # name
  local f="$OUT/$1.pid"
  [ -f "$f" ] || return 0
  local p; p=$(cat "$f")
  if kill "$p" 2>/dev/null; then
    for _ in $(seq 50); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
    wait "$p" 2>/dev/null  # reap quietly (suppresses bash "Terminated" notices)
  fi
  rm -f "$f"
}

start_bg() { # name logfile cmd...
  local name=$1 log=$2; shift 2
  nohup "$@" > "$log" 2>&1 &
  echo $! > "$OUT/$name.pid"
}

gw_restart() { # config logname
  stop_pid agw
  start_bg agw "$OUT/agw-$2.log" bin/agentgateway -f "$1"
  wait_port 127.0.0.1:3300
}

callout_start() { # extra args...
  stop_pid callout
  start_bg callout "$OUT/callout.log" bin/callout "$@"
  wait_port 127.0.0.1:9001
}

stop_all() { for n in agw callout mcpserver otlpsink; do stop_pid $n; done; }
