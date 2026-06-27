#!/usr/bin/env python3
"""Test Go alert-worker with a synthetic FAILED gate result."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "reports" / "GATE_RESULT.json"


class Handler(BaseHTTPRequestHandler):
    last_body: bytes = b""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        Handler.last_body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        return


def main() -> int:
    GATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    GATE_PATH.write_text(
        json.dumps(
            {
                "passed": False,
                "reasons": ["CRITICAL: plaintext secret in application code: src/main.py:1"],
                "summary_path": "reports/CI_SUMMARY.md",
                "repository": "jhnnnp/K-SecOps",
                "ref": "refs/pull/2/merge",
            }
        ),
        encoding="utf-8",
    )

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    webhook = f"http://127.0.0.1:{port}/hook"
    env = os.environ.copy()
    env["SECOPS_ALERT_WEBHOOK"] = webhook
    env["SECOPS_GATE_RESULT_PATH"] = str(GATE_PATH)
    env["SECOPS_ALERT_FORMAT"] = "slack"

    result = subprocess.run(
        ["go", "run", "./cmd/alert-worker"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    server.shutdown()

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        return result.returncode

    body = json.loads(Handler.last_body.decode("utf-8"))
    assert "FAILED" in body.get("text", ""), body
    print("OK: Go alert-worker posted webhook payload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
