"""Local read-only dashboard for Umbra reports (binds to 127.0.0.1 only)."""
from __future__ import annotations

import html
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SAFE = re.compile(r"^umbra_[A-Za-z0-9._-]+\.(html|pdf|json)$")
CT = {".html": "text/html; charset=utf-8", ".pdf": "application/pdf", ".json": "application/json"}


def _index(rdir: Path) -> str:
    rows = []
    for jp in sorted(rdir.glob("umbra_*.json"), reverse=True)[:100]:
        try:
            d = json.loads(jp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        links = " ".join(f'<a href="/r/{html.escape(jp.with_suffix(e).name)}">{e[1:]}</a>'
                         for e in (".html", ".pdf", ".json") if jp.with_suffix(e).exists())
        c = d.get("counts", {})
        scope = ", ".join(d.get("scope", {}).get("domains", []) + d.get("scope", {}).get("hosts", []))
        rows.append(f"<tr><td>{html.escape(d.get('finished', ''))}</td><td>{html.escape(scope)}</td>"
                    f"<td><b>{html.escape(str(d.get('grade')))}</b> {d.get('score')}</td>"
                    f"<td>C{c.get('critical', 0)} H{c.get('high', 0)} M{c.get('medium', 0)} L{c.get('low', 0)}</td>"
                    f"<td>{links}</td></tr>")
    body = "".join(rows) or "<tr><td colspan=5>No reports yet — run <code>python umbra.py scan</code>.</td></tr>"
    return ("<!doctype html><meta charset=utf-8><title>Umbra</title><style>body{font:15px system-ui;margin:30px auto;"
            "max-width:960px;padding:0 16px;color-scheme:light dark}td,th{padding:6px 10px;border-bottom:1px solid #8884;"
            "text-align:left}a{margin-right:8px}</style><h1>🌑 Umbra reports</h1><table><tr><th>When</th><th>Scope</th>"
            f"<th>Score</th><th>Severity</th><th>Open</th></tr>{body}</table>")


def serve(cfg, port: int = 8788) -> int:
    rdir = (cfg.data_dir / "reports").resolve()
    rdir.mkdir(parents=True, exist_ok=True)

    class H(BaseHTTPRequestHandler):
        def _send(self, code, data: bytes, ctype="text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path == "/":
                return self._send(200, _index(rdir).encode())
            m = re.fullmatch(r"/r/([^/]+)", self.path)
            if m and SAFE.match(m.group(1)):
                f = (rdir / m.group(1)).resolve()
                if f.parent == rdir and f.exists():
                    return self._send(200, f.read_bytes(), CT[f.suffix])
            self._send(404, b"not found", "text/plain")

        def log_message(self, *a):  # quiet
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print(f"Dashboard: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
