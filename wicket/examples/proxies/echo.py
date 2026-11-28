"""The upstream app for proxies.sh: answers every request with what reached it.

It prints the method, the path exactly as the proxy sent it, and the
identity headers, so the check can see what the app would have trusted.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Echo(BaseHTTPRequestHandler):
    def answer(self):
        body = json.dumps({
            "method": self.command,
            "path": self.path,
            "user": self.headers.get("X-Auth-User", ""),
            "email": self.headers.get("X-Auth-Email", ""),
            "groups": self.headers.get("X-Auth-Groups", ""),
            "provider": self.headers.get("X-Auth-Provider", ""),
            "token": bool(self.headers.get("X-Auth-Token", "")),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # The same answer in a header, so a HEAD request shows it too.
        self.send_header("X-Echo", body.decode())
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = answer

    def log_message(self, fmt, *args):
        sys.stderr.write("echo: " + (fmt % args) + "\n")


ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Echo).serve_forever()
