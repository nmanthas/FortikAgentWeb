#!/usr/bin/env python3
"""A LOCAL stand-in for a job system's webhook (DEV / DEMO ONLY).

Fortik's queue_webhook integration POSTs pause / resume / cancel requests,
signed with HMAC-SHA256 (X-Fortik-Signature). This receiver verifies the
signature and prints one line per request, so a presenter can show that a
suspend really paused queued work. It is the same receiver that
scripts/demo-phase4.sh starts.

    python3 scripts/fakes/queue_webhook_receiver.py <port> <shared-secret>
"""
import hashlib
import hmac
import http.server
import json
import sys

PORT, SECRET = int(sys.argv[1]), sys.argv[2].encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        want = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(want, self.headers.get("X-Fortik-Signature", ""))
        try:
            d = json.loads(body)
            line = f"{d.get('action')} {d.get('agent_id')}"
        except ValueError:
            line = "unparseable body"
        print(f"job system received: {line}  [{'signature OK' if ok else 'BAD SIGNATURE: rejected'}]", flush=True)
        self.send_response(200 if ok else 401)
        self.end_headers()

    def log_message(self, *args):
        pass


print(f"local job-system webhook listening on 127.0.0.1:{PORT} (Ctrl+C to stop)", flush=True)
http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
