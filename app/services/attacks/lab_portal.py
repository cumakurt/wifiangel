"""Lab captive portal for authorized Evil Twin sessions.

Serves a labeled assessment page and records HTTP hits (client IP, path,
user-agent). It does not present a password form.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

PORTAL_BIND_IP = "192.168.1.1"
PORTAL_PORT = 80

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WiFiAngel lab portal</title>
  <style>
    body { font-family: sans-serif; max-width: 36rem; margin: 3rem auto; padding: 0 1rem; }
    .banner { border: 1px solid #444; padding: 1rem 1.25rem; }
    button { padding: 0.5rem 1rem; }
  </style>
</head>
<body>
  <div class="banner">
    <h1>WiFiAngel authorized lab portal</h1>
    <p>This access point is a controlled wireless lab. HTTP from this subnet
    is steered here so operators can see captive-portal detection and client hits.</p>
    <form method="post" action="/continue">
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>
"""


class PortalState:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.lock = threading.Lock()
        self.hits: list[dict[str, Any]] = []

    def record(self, client: str, method: str, path: str, user_agent: str) -> None:
        row = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "client": client,
            "method": method,
            "path": path,
            "user_agent": user_agent[:200],
        }
        with self.lock:
            self.hits.append(row)
            try:
                with self.log_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(row) + "\n")
            except OSError:
                pass

    @property
    def hit_count(self) -> int:
        with self.lock:
            return len(self.hits)


def _handler_class(state: PortalState):
    class LabPortalHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            self._serve("GET")

        def do_HEAD(self) -> None:
            self._serve("HEAD", body=False)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if 0 < length <= 4096:
                self.rfile.read(length)
            self._serve("POST")

        def _serve(self, method: str, *, body: bool = True) -> None:
            path = urlparse(self.path).path or "/"
            client = self.client_address[0] if self.client_address else ""
            agent = self.headers.get("User-Agent") or ""
            state.record(client, method, path, agent)
            payload = _PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            if body:
                self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if body:
                self.wfile.write(payload)

    return LabPortalHandler


class LabCaptivePortal:
    def __init__(self, bind_ip: str, log_path: Path, *, port: int = PORTAL_PORT):
        self.bind_ip = bind_ip
        self.port = port
        self.state = PortalState(log_path)
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = _handler_class(self.state)

        class _Server(ThreadingHTTPServer):
            allow_reuse_address = True

        self._httpd = _Server((self.bind_ip, self.port), handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def bound_port(self) -> int:
        if self._httpd is None:
            return 0
        return int(self._httpd.server_address[1])

    def stop(self) -> None:
        httpd = self._httpd
        if httpd is None:
            return
        try:
            httpd.shutdown()
        except Exception:
            pass
        try:
            httpd.server_close()
        except Exception:
            pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        self._httpd = None
        self._thread = None

    @property
    def hit_count(self) -> int:
        return self.state.hit_count
