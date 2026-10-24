"""Check YOUR web servers for files that should never be public."""
from __future__ import annotations

import re
import uuid

from core.plugin_base import Module
from utils import http

# path -> (validator on body, severity, label)
CHECKS = {
    "/.git/HEAD": (lambda b: b.startswith("ref:"), "critical", "Git repository exposed"),
    "/.env": (lambda b: "=" in b and "<html" not in b[:200].lower() and len(b) < 20000, "critical", ".env file exposed"),
    "/.svn/entries": (lambda b: "dir" in b[:50] or b[:2].isdigit(), "high", "SVN metadata exposed"),
    "/.DS_Store": (lambda b: "Bud1" in b[:20], "low", ".DS_Store exposed"),
    "/phpinfo.php": (lambda b: "phpinfo()" in b or "PHP Version" in b, "high", "phpinfo() page exposed"),
    "/server-status": (lambda b: "Apache Server Status" in b, "medium", "Apache server-status exposed"),
    "/actuator/env": (lambda b: '"propertySources"' in b or '"activeProfiles"' in b, "critical", "Spring Actuator /env exposed"),
    "/wp-config.php.bak": (lambda b: "DB_PASSWORD" in b, "critical", "WordPress config backup exposed"),
    "/backup.zip": (lambda b: b[:2] == "PK", "high", "Backup archive exposed"),
    "/config.json": (lambda b: any(k in b.lower() for k in ('"password"', '"secret"', '"api_key"', '"token"')), "high", "Config file with secrets exposed"),
    "/": (lambda b: "<title>Index of /" in b, "medium", "Directory listing enabled"),
}
FIX = ("# nginx\nlocation ~ /\\.(git|svn|env|DS_Store) { deny all; return 404; }\n"
       "# apache\n<FilesMatch \"^\\.(git|svn|env|DS_Store)\">\n  Require all denied\n</FilesMatch>\n"
       "# remove the file from the web root and ROTATE any credentials it contained")


class Exposure(Module):
    name = "exposure"
    description = "Detect sensitive files/endpoints accidentally exposed on your web servers"
    category = "web"

    def run(self, ctx):
        timeout = ctx.cfg.get("scan.timeout", 6)
        s = http.session(ctx.cfg.get("scan.user_agent"))
        for host, scheme, port in ctx.web_endpoints():
            base = f"{scheme}://{host}" + ("" if (scheme, port) in (("http", 80), ("https", 443)) else f":{port}")
            ident = base.split("://", 1)[1]
            canary = http.fetch(s, f"{base}/{uuid.uuid4().hex}", timeout, allow_redirects=False)
            if canary is None:
                continue
            soft404 = canary.status_code == 200      # server answers 200 for anything → body checks must carry the weight
            for path, (validator, sev, label) in CHECKS.items():
                r = http.fetch(s, base + path, timeout, allow_redirects=False, stream=True)
                if r is None or r.status_code != 200:
                    continue
                body = r.raw.read(20000, decode_content=True).decode("utf-8", "replace")
                r.close()
                if soft404 and path != "/" and body[:300] == (canary.text or "")[:300]:
                    continue
                if validator(body):
                    ctx.add_finding(rule="exposure." + (re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_") or "dirlist"), module=self.name, severity=sev,
                                    asset=ident, title=label, evidence=f"{base}{path} returned HTTP 200",
                                    description="Publicly readable files like this routinely leak source, credentials or internal structure.",
                                    remediation="Block access at the web server, delete the file from the web root, and rotate anything it exposed.",
                                    fix_snippet=FIX, discriminator=path, references=["OWASP A05: Security Misconfiguration"])
