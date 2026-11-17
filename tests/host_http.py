from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAYLOAD = (b"PASSWALL_SSH_CORE_VM_OK\n" * 65536)[:1048576]

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != "/payload":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
