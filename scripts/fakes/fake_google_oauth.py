#!/usr/bin/env python3
"""A LOCAL FAKE of Google's OAuth endpoints for the Phase 6 demo. It is not Google.

  GET  /auth     the "consent screen": approves at once and redirects back with a code
  POST /token    authorization_code and refresh_token grants
  POST /revoke   revokes a refresh token
  GET  /state    what the fake holds (live grants, revocations) for the demo's checks

Usage: fake_google_oauth.py PORT CLIENT_ID CLIENT_SECRET
"""
import json
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, CLIENT_ID, CLIENT_SECRET = int(sys.argv[1]), sys.argv[2], sys.argv[3]
codes, refresh, revoked = {}, set(), []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, headers=None):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/auth":
            if q.get("client_id") != CLIENT_ID:
                return self.send(400, {"error": "invalid_client"})
            code = "fake-code-" + secrets.token_hex(6)
            codes[code] = q.get("scope", "")
            loc = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q.get("state", "")})
            return self.send(302, {}, {"Location": loc})
        if u.path == "/state":
            return self.send(200, {"live_grants": len(refresh), "revoked": len(revoked)})
        self.send(404, {})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        f = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        if self.path == "/revoke":
            refresh.discard(f.get("token"))
            revoked.append(f.get("token"))
            return self.send(200, {})
        if self.path != "/token":
            return self.send(404, {})
        if f.get("client_id") != CLIENT_ID or f.get("client_secret") != CLIENT_SECRET:
            return self.send(401, {"error": "invalid_client"})
        if f.get("grant_type") == "authorization_code":
            if f.get("code") not in codes:
                return self.send(400, {"error": "invalid_grant"})
            codes.pop(f["code"])
            rt = "1//fake-refresh-" + secrets.token_hex(8)
            refresh.add(rt)
            return self.send(200, {"access_token": "ya29.fake-" + secrets.token_hex(8), "refresh_token": rt, "expires_in": 3599, "token_type": "Bearer"})
        if f.get("grant_type") == "refresh_token":
            if f.get("refresh_token") not in refresh:
                return self.send(400, {"error": "invalid_grant"})
            return self.send(200, {"access_token": "ya29.fake-" + secrets.token_hex(8), "expires_in": 3599, "token_type": "Bearer"})
        self.send(400, {"error": "unsupported_grant_type"})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
