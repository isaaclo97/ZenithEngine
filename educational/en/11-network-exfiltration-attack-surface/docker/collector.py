#!/usr/bin/env python3
"""Minimal HTTP collector acting as the "attacker's server": it prints to
its own output any request it receives, just as a real attacker collecting
exfiltrated data would see it. It only listens on docker-compose's
internal, isolated network (network internal: true) -- it never reaches
the Internet."""
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode(errors='replace')
        print('=' * 60, flush=True)
        print(f'[collector] Request received at {self.path}', flush=True)
        print(f'[collector] Body: {body}', flush=True)
        print('=' * 60, flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
        # Give the response time to reach the client before the process exits.
        threading.Timer(1.0, lambda: os._exit(0)).start()

    def log_message(self, format, *args):
        pass  # silence the standard access log, we use the print() above instead


if __name__ == '__main__':
    print('[collector] Listening on 0.0.0.0:8080 (internal network, no Internet access)...', flush=True)
    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
