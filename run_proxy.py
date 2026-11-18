import os
import sys
import socket
import signal
import http.server
import socketserver
import urllib.request
import urllib.error
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

DEFAULT_PORT = int(os.environ.get("WORKBENCH_PROXY_PORT", "9000"))
TARGET_BACKEND = os.environ.get("WORKBENCH_TARGET_URL", "http://127.0.0.1:8000")

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks whether the specified port is already bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) == 0

def check_existing_proxy_healthy(port: int) -> bool:
    """Probes if an active process on port is already serving the workbench health endpoint."""
    test_urls = [
        f"http://127.0.0.1:{port}/http://127.0.0.1:8000/api/health",
        f"http://127.0.0.1:{port}/api/health"
    ]
    for url in test_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WorkbenchProxyProbe/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            continue
    return False

class ReverseProxyHandler(http.server.BaseHTTPRequestHandler):
    """
    Transparent reverse proxy supporting subpath URLs (e.g. /http://127.0.0.1:8000/...)
    as well as standard SPA assets, API routes, and CORS headers.
    """
    server_version = "ForensicsWorkbenchProxy/2.0"

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._proxy_request("GET")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None
        self._proxy_request("POST", body)

    def do_PUT(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None
        self._proxy_request("PUT", body)

    def do_PATCH(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None
        self._proxy_request("PATCH", body)

    def do_DELETE(self):
        self._proxy_request("DELETE")

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def _proxy_request(self, method: str, body: bytes = None):
        path = self.path
        
        # Route resolution:
        # If path starts with /http://127.0.0.1:8000 or /http://localhost:8000
        if path.startswith("/http://127.0.0.1:8000"):
            subpath = path[len("/http://127.0.0.1:8000"):] or "/"
            target_url = f"{TARGET_BACKEND}{subpath}"
        elif path.startswith("/http://localhost:8000"):
            subpath = path[len("/http://localhost:8000"):] or "/"
            target_url = f"{TARGET_BACKEND}{subpath}"
        else:
            # Direct relative routes (/api/..., /assets/..., /)
            target_url = f"{TARGET_BACKEND}{path}"

        headers = {}
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "connection"):
                headers[k] = v

        try:
            req = urllib.request.Request(target_url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                self.send_response(resp.status)
                for hk, hv in resp.getheaders():
                    if hk.lower() not in ("transfer-encoding", "content-length", "connection", "access-control-allow-origin"):
                        self.send_header(hk, hv)
                self._send_cors_headers()
                content = resp.read()
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self._send_cors_headers()
            err_content = e.read()
            self.send_header("Content-Length", str(len(err_content)))
            self.end_headers()
            self.wfile.write(err_content)
        except Exception as e:
            self.send_response(502)
            self._send_cors_headers()
            msg = f"Bad Gateway: Unable to connect to backend at {TARGET_BACKEND}. Error: {str(e)}".encode()
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def log_message(self, format, *args):
        # Silent logging by default to prevent console clutter; prints errors
        if args and len(args) > 1 and str(args[1]).startswith(("4", "5")):
            sys.stderr.write(f"[Proxy {args[1]}] {args[0]}\n")

class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def run():
    port = DEFAULT_PORT

    print("=" * 70)
    print(" FORENSICS WORKBENCH — REVERSE PROXY & WEB PREVIEW GATEWAY ")
    print("=" * 70)
    print(f"[*] Gateway Port      : {port}")
    print(f"[*] Target Backend    : {TARGET_BACKEND}")

    # Check for port conflict
    if is_port_in_use(port):
        if check_existing_proxy_healthy(port):
            print(f"[+] Proxy is already active and healthy on port {port}.")
            print(f"[+] Web Preview URL   : http://127.0.0.1:{port}/{TARGET_BACKEND}/")
            print("=" * 70)
            sys.exit(0)
        else:
            print(f"[!] Warning: Port {port} is occupied by an external service.")
            print(f"    Reverse proxy gateway will not bind to port {port}.")
            print("    Workbench direct access available at http://127.0.0.1:8000")
            print("=" * 70)
            sys.exit(0)

    try:
        with ReusableTCPServer(("127.0.0.1", port), ReverseProxyHandler) as httpd:
            print(f"[+] Gateway Listening : http://127.0.0.1:{port}/")
            print(f"[+] Web Preview URL   : http://127.0.0.1:{port}/{TARGET_BACKEND}/")
            print("=" * 70)

            def shutdown_signal(signum, frame):
                print("\n[*] Shutting down reverse proxy gateway...")
                httpd.shutdown()
                sys.exit(0)

            signal.signal(signal.SIGINT, shutdown_signal)
            signal.signal(signal.SIGTERM, shutdown_signal)

            httpd.serve_forever()
    except Exception as e:
        print(f"[X] Proxy initialization error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run()

