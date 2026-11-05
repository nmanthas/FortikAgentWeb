#!/usr/bin/env python3
"""LOCAL stand-ins behind agentgateway (DEV / DEMO ONLY), for
scripts/demo-agentgateway.sh:

  - an A2A agent server (JSON-RPC message/send): answers with a task that is
    still "working", so the delegation hop stays open;
  - an outside HTTP API: answers {"ok": true}.

Each request is appended as one JSON line to the log: which upstream, the
agent identity agentgateway injected (x-fortik-agent-id), whether an
Authorization header leaked through (it must not), and the delegation token
the delegated agent received (so the demo can act "for" the delegator).

    python3 scripts/fakes/agent_upstreams.py <a2a-port> <http-port> <log-file>
"""
import http.server
import json
import sys
import threading

A2A_PORT, HTTP_PORT, LOG = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
lock = threading.Lock()


def record(kind, h):
    line = {
        "upstream": kind,
        "agent_id": h.headers.get("x-fortik-agent-id", ""),
        "action_id": h.headers.get("x-fortik-action-id", ""),
        "authorization_seen": bool(h.headers.get("Authorization")),
        "delegation": h.headers.get("x-fortik-delegation", ""),
        "path": h.path,
    }
    with lock, open(LOG, "a") as f:
        f.write(json.dumps(line) + "\n")


class A2A(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
        try:
            req = json.loads(body)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        record("a2a", self)
        out = {"jsonrpc": "2.0", "id": req.get("id"), "result": {
            "kind": "task", "id": "task-research-1", "contextId": "ctx-1",
            "status": {"state": "working"}}}
        b = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class API(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        record("http", self)
        b = b'{"ok": true, "report": "partner pricing sheet"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


servers = [http.server.ThreadingHTTPServer(("127.0.0.1", A2A_PORT), A2A),
           http.server.ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), API)]
for s in servers[1:]:
    threading.Thread(target=s.serve_forever, daemon=True).start()
servers[0].serve_forever()
