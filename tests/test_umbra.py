"""Offline tests: unit tests + an integration run against a local lab (no internet needed)."""
import datetime as dt
import http.server
import json
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import notifier, plugin_base                      # noqa: E402
from core.config import Config                               # noqa: E402
from core.inventory import Inventory                         # noqa: E402
from core.models import Asset, Finding, ScanJob              # noqa: E402
from core.orchestrator import inventory_path, run_scan       # noqa: E402
from modules.secrets import scan_text                        # noqa: E402


def make_cert(tmp: Path, days: int):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab.local")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    (tmp / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                  serialization.NoEncryption()))
    return str(tmp / "c.pem"), str(tmp / "k.pem")


class LabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        routes = {"/.env": "DB_PASSWORD=Sup3rS3cretValue\nAPP=1\n", "/.git/HEAD": "ref: refs/heads/main\n",
                  "/": "<html><title>lab</title></html>"}
        body = routes.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.send_header("Server", "nginx/1.18.0")
        if self.path == "/":
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
        data = (body or "nope").encode()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def serve(port_holder, tls=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    if tls:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(*tls)
        srv.socket = c.wrap_socket(srv.socket, server_side=True)
    port_holder.append(srv.server_address[1])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    def loop():
        while True:
            try:
                s.accept()[0].close()
            except OSError:
                return
    threading.Thread(target=loop, daemon=True).start()
    return s, s.getsockname()[1]


class UnitTests(unittest.TestCase):
    def test_secret_detection_and_redaction(self):
        text = 'aws = "AKIAZ3MQ7K2B5N4P6R8T"\npassword = "changeme123"\nx = "ok"  # umbra:ignore AKIAZ3MQ7K2B5N4P6R8T\n'
        hits = list(scan_text(text))
        self.assertEqual([h[1] for h in hits], ["aws_access_key"])
        self.assertNotIn("Z3MQ7K2B5N4P6R8T", hits[0][4])
        self.assertTrue(hits[0][4].startswith("AKIA"))

    def test_generic_secret_entropy(self):
        self.assertTrue(list(scan_text('api_key = "k8Zq2LmX9vT4rBw7NpYc"')))  # umbra:ignore
        self.assertFalse(list(scan_text('api_key = "aaaaaaaaaaaa"')))

    def test_inventory_diff_and_scoping(self):
        with tempfile.TemporaryDirectory() as td:
            inv = Inventory(Path(td) / "i.json")
            a, b = Asset("port", "1.1.1.1:22"), Asset("subdomain", "x.example.com")
            new, gone = inv.update_assets({a.key: a, b.key: b}, {"port", "subdomain"})
            self.assertEqual(len(new), 2)
            new, gone = inv.update_assets({b.key: b}, {"port"})        # only ports were scanned
            self.assertEqual(gone, [a.key])
            self.assertIn(b.key, inv.data["assets"])                   # subdomain not scanned → retained
            inv.suppress("abc", "fp"); inv.save()
            self.assertIn("abc", Inventory(Path(td) / "i.json").suppressed)

    def test_score_grade_and_alert(self):
        job = ScanJob(profile="t", scope={"domains": ["e.com"]})
        job.findings = [Finding("r", "m", "Bad thing", "critical", "e.com")]
        self.assertEqual((job.score(), job.grade()), (75, "B"))
        job.diff = {"new_findings": [job.findings[0].fingerprint], "new_assets": [], "gone_assets": [], "resolved_findings": []}
        cfg = Config.load()
        self.assertIn("Bad thing", notifier.build_alert(job, cfg))
        job.first_run = True
        self.assertIsNone(notifier.build_alert(job, cfg))

    def test_notifier_chunks(self):
        self.assertTrue(all(len(c) <= 100 for c in notifier._chunks("line\n" * 100, 100)))


class DnsTests(unittest.TestCase):
    def test_dns_hygiene_with_mocked_resolver(self):
        import logging
        from unittest import mock
        from modules.dns_hygiene import DnsHygiene
        zone = {("e.com", "TXT"): ["v=spf1 +all"], ("_dmarc.e.com", "TXT"): ["v=DMARC1; p=none"]}
        cfg = Config.load()
        cfg.set("scope", {"domains": ["e.com"], "hosts": [], "paths": [], "exclude": []})
        ctx = plugin_base.ScanContext(cfg, logging.getLogger("t"))
        ctx.cnames["old.e.com"] = "gone.github.io"
        with mock.patch("utils.net.resolve", lambda h, t="A", timeout=4: zone.get((h, t), [])), \
             mock.patch("utils.net.is_nxdomain", lambda h, timeout=4: True):
            DnsHygiene().run(ctx)
        rules = {f.rule: f.severity for f in ctx.findings}
        self.assertEqual(rules["dns.spf_permissive"], "high")
        self.assertIn("dns.dmarc_monitor_only", rules)
        self.assertIn("dns.caa_missing", rules)
        self.assertEqual(rules["dns.dangling_cname"], "high")          # github.io = takeover-prone


class LabIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.https_p, cls.http_p = [], []
        cls.s1 = serve(cls.https_p, make_cert(t, days=3))
        cls.s2 = serve(cls.http_p)
        plugin_base.WEB_PORTS[cls.https_p[0]] = "https"
        plugin_base.WEB_PORTS[cls.http_p[0]] = "http"
        cls.db_sock, cls.db_port = listener()
        (t / "repo").mkdir()
        (t / "repo" / "app.py").write_text('KEY = "AKIAZ3MQ7K2B5N4P6R8T"\n')  # umbra:ignore (fake test credential)
        cls.cfg = Config.load()
        cls.cfg.set("app.data_dir", str(t / "data"))
        cls.cfg.set("scope", {"domains": [], "hosts": ["127.0.0.1"], "paths": [str(t / "repo")], "exclude": []})
        cls.cfg.set("scan.ports", [cls.https_p[0], cls.http_p[0], cls.db_port])
        cls.cfg.set("scan.timeout", 3)
        cls.cfg.set("policy.allowed_ports", [cls.https_p[0]])
        cls.cfg.set("notifications", {"min_severity": "low"})
        cls.out = t / "reports"

    @classmethod
    def tearDownClass(cls):
        for s in (cls.s1, cls.s2):
            s.shutdown()
        cls.db_sock.close()
        cls.tmp.cleanup()

    def scan(self):
        return run_scan(self.cfg, profile="full", out_dir=self.out, dry_notify=True)

    def test_full_flow(self):
        job, paths, alert, _ = self.scan()
        rules = {f.rule for f in job.findings}
        for r in ("headers.missing", "headers.version_disclosure", "headers.cookie_flags", "headers.no_https_redirect",
                  "exposure.env", "exposure.git_head", "tls.invalid_chain", "tls.expiring_soon",
                  "ports.unexpected", "secrets.aws_access_key"):
            self.assertIn(r, rules, f"missing rule {r}; got {sorted(rules)}")
        self.assertTrue(job.first_run)
        self.assertIsNone(alert)                                       # first run → baseline only
        for fmt in ("html", "pdf", "json"):
            self.assertIn(fmt, paths)
        self.assertEqual(Path(paths["pdf"]).read_bytes()[:4], b"%PDF")
        html = Path(paths["html"]).read_text()
        self.assertIn("Remediation plan", html)
        self.assertNotIn("Z3MQ7K2B5N4P6R8T", html + json.dumps(json.load(open(paths["json"]))))  # secret never leaks

        # 2nd run: nothing new
        job2, _, alert2, _ = self.scan()
        self.assertFalse(job2.first_run)
        self.assertEqual(job2.diff["new_findings"], [])
        self.assertIsNone(alert2)

        # a new listener appears → alert
        s, port = listener()
        plugin_base.WEB_PORTS.pop(port, None)
        self.cfg.set("scan.ports", [self.https_p[0], self.http_p[0], self.db_port, port])
        job3, _, alert3, sent = self.scan()
        s.close()
        self.assertTrue(any(str(port) in k for k in job3.diff["new_assets"]))
        self.assertIn("New assets", alert3)

        # operator intervention: suppress one finding, accept baseline
        fp = job3.findings[0].fingerprint
        inv = Inventory(inventory_path(self.cfg))
        inv.suppress(fp, "test"); inv.approve_all_known("test"); inv.save()
        job4, *_ = self.scan()
        self.assertNotIn(fp, [f.fingerprint for f in job4.findings])
        self.assertFalse([f for f in job4.findings if f.rule.startswith("ports.unexpected")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
