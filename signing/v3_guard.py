"""Expose only Anisette V3 endpoints to the pinned SideSign client.

SideSign 0.1.7 can otherwise fall back to a shared V1 device identity after a
V3 headers request fails. A per-process loopback relay makes that fallback fail
closed while keeping the upstream TLS and server identity checks enabled.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from common import SigningError

_MAX_BODY = 1024 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@contextmanager
def v3_only_server(upstream):
    parsed = urlsplit(upstream)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise SigningError('invalid_anisette_server')
    upstream = upstream.rstrip('/')
    token = secrets.token_urlsafe(32)
    prefix = '/' + token
    opener = build_opener(_NoRedirect())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def respond(self, status, body=b''):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def forward(self, path, body=None):
            try:
                headers = {'Content-Type': 'application/json'} if body is not None else {}
                request = Request(upstream + path, data=body, headers=headers)
                with opener.open(request, timeout=12) as response:
                    result = response.read(_MAX_BODY + 1)
                    if len(result) > _MAX_BODY:
                        raise ValueError('response_too_large')
                    value = json.loads(result)
                    if not isinstance(value, dict):
                        raise ValueError('response_not_object')
                self.respond(200, result)
            except (HTTPError, URLError, OSError, ValueError, TimeoutError):
                self.respond(502, b'{}')

        def do_GET(self):
            if self.path == prefix + '/v3/client_info':
                self.forward('/v3/client_info')
            else:
                # In particular, never forward V1 GET /.
                self.respond(404, b'{}')

        def do_POST(self):
            if self.path != prefix + '/v3/get_headers':
                self.respond(404, b'{}')
                return
            try:
                size = int(self.headers.get('Content-Length', '-1'))
                if not 0 < size <= _MAX_BODY:
                    raise ValueError('invalid_size')
                self.connection.settimeout(12)
                body = self.rfile.read(size)
                value = json.loads(body)
                if (len(body) != size or not isinstance(value, dict) or
                        set(value) != {'identifier', 'adi_pb'} or
                        not all(isinstance(v, str) for v in value.values())):
                    raise ValueError('invalid_request')
            except (ValueError, OSError):
                self.respond(400, b'{}')
                return
            self.forward('/v3/get_headers', body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:%d%s' % (server.server_address[1], prefix)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
