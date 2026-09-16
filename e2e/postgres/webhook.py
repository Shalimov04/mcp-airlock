"""Slack-style webhook receiver: POST stores the JSON body, GET returns everything received."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MESSAGES: list = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        MESSAGES.append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        body = json.dumps(MESSAGES).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
