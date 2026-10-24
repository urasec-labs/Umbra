"""Example custom module. Rename to remove the leading underscore to activate it:
    mv plugins/_example_security_txt.py plugins/security_txt.py
then add `security_txt` to a profile in config/umbra.yaml (or run: umbra scan -m security_txt).
"""
from core.plugin_base import Module
from utils import http


class SecurityTxt(Module):
    name = "security_txt"
    description = "Check that /.well-known/security.txt exists (RFC 9116)"
    category = "web"

    def run(self, ctx):
        s = http.session(ctx.cfg.get("scan.user_agent"))
        for host, scheme, port in ctx.web_endpoints():
            if scheme != "https":
                continue
            r = http.fetch(s, f"https://{host}:{port}/.well-known/security.txt", ctx.cfg.get("scan.timeout", 6))
            if r is not None and r.status_code != 200:
                ctx.add_finding(rule="web.security_txt_missing", module=self.name, severity="info",
                                asset=f"{host}:{port}", title="No security.txt",
                                remediation="Publish a security.txt so researchers know how to report issues.",
                                fix_snippet="Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:00Z\nPreferred-Languages: en, tr")
