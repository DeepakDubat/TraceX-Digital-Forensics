import http.server
import socketserver
import urllib.request
import urllib.error
import sys

PORT = 9000

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len) if content_len > 0 else None
        self._proxy_request('POST', body)

    def _proxy_request(self, method, body=None):
        path = self.path
        # Handle prefix /http://127.0.0.1:8000/
        if path.startswith('/http://127.0.0.1:8000'):
            target_subpath = path[len('/http://127.0.0.1:8000'):]
            if not target_subpath:
                target_subpath = '/'
            target_url = f"http://127.0.0.1:8000{target_subpath}"
        elif path.startswith('/assets/'):
            target_url = f"http://127.0.0.1:8000{path}"
        elif path.startswith('/api/'):
            target_url = f"http://127.0.0.1:8000{path}"
        else:
            target_url = f"http://127.0.0.1:8000{path}"

        headers = {}
        for k, v in self.headers.items():
            if k.lower() not in ('host', 'content-length'):
                headers[k] = v

        try:
            req = urllib.request.Request(target_url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for hk, hv in resp.getheaders():
                    if hk.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                        self.send_header(hk, hv)
                content = resp.read()
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    with socketserver.TCPServer(('127.0.0.1', PORT), ProxyHandler) as httpd:
        print(f"Proxy server running on port {PORT} forwarding to http://127.0.0.1:8000")
        httpd.serve_forever()

