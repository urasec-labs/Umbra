"""HTTP security headers, cookie flags, HTTPS redirect and version disclosure."""
from __future__ import annotations

from core.plugin_base import Module
from utils import http

HEADER_FIX = {
    "strict-transport-security": ("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;", "high"),
    "content-security-policy": ("add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'\" always;", "medium"),
    "x-content-type-options": ("add_header X-Content-Type-Options \"nosniff\" always;", "low"),
    "referrer-policy": ("add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;", "low"),
    "permissions-policy": ("add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;", "low"),
    "x-frame-options": ("add_header X-Frame-Options \"SAMEORIGIN\" always;", "low"),
}
APACHE = {"strict-transport-security": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
          "content-security-policy": "Header always set Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\"",
          "x-content-type-options": 'Header always set X-Content-Type-Options "nosniff"',
          "referrer-policy": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
          "permissions-policy": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
          "x-frame-options": 'Header always set X-Frame-Options "SAMEORIGIN"'}
SEV_ORDER = ["info", "low", "medium", "high", "critical"]


class Headers(Module):
    name = "headers"
    description = "Security headers, cookie flags, HTTP→HTTPS redirect, version disclosure"
    category = "web"

    def run(self, ctx):
        cfg = ctx.cfg
        timeout = cfg.get("scan.timeout", 6)
        s = http.session(cfg.get("scan.user_agent"))
        required = [h.lower() for h in cfg.get("policy.required_headers", [])]
        for host, scheme, port in ctx.web_endpoints():
            base = f"{scheme}://{host}" + ("" if (scheme, port) in (("http", 80), ("https", 443)) else f":{port}")
            r = http.fetch(s, base + "/", timeout, allow_redirects=False)
            if r is None:
                continue
            ident = base.split("://", 1)[1]
            h = {k.lower(): v for k, v in r.headers.items()}
            redirect = 300 <= r.status_code < 400

            if scheme == "http":
                loc = h.get("location", "")
                if r.status_code < 400 and not (redirect and loc.startswith("https://")):
                    ctx.add_finding(rule="headers.no_https_redirect", module=self.name, severity="medium", asset=ident,
                                    title="HTTP does not redirect to HTTPS", evidence=f"HTTP {r.status_code}",
                                    remediation="Redirect all plain-HTTP traffic to HTTPS.",
                                    fix_snippet="# nginx\nserver { listen 80; server_name _; return 301 https://$host$request_uri; }")
                continue          # header checks are only meaningful on HTTPS responses
            if redirect:
                continue

            missing = [x for x in required if x not in h]
            if "x-frame-options" in missing and "frame-ancestors" in h.get("content-security-policy", ""):
                missing.remove("x-frame-options")
            if missing:
                worst = max((HEADER_FIX.get(m, ("", "low"))[1] for m in missing), key=SEV_ORDER.index)
                ctx.add_finding(
                    rule="headers.missing", module=self.name, severity=worst, asset=ident,
                    title="Missing security headers", evidence=", ".join(missing),
                    description="These response headers harden browsers against XSS, clickjacking, MIME sniffing and downgrade attacks.",
                    remediation="Add the headers at your reverse proxy / web server (snippets below), then re-scan. Test CSP in report-only mode first.",
                    fix_snippet="# nginx (server or location block)\n" + "\n".join(HEADER_FIX[m][0] for m in missing if m in HEADER_FIX)
                                + "\n\n# apache (mod_headers)\n" + "\n".join(APACHE[m] for m in missing if m in APACHE),
                    discriminator=",".join(sorted(missing)),
                    references=["OWASP Secure Headers Project"])
            for hdr in ("server", "x-powered-by", "x-aspnet-version"):
                v = h.get(hdr, "")
                if v and any(c.isdigit() for c in v):
                    ctx.add_finding(rule="headers.version_disclosure", module=self.name, severity="low", asset=ident,
                                    title="Server discloses software version", evidence=f"{hdr}: {v[:80]}",
                                    description="Version banners help attackers pick known exploits.",
                                    remediation="Hide version information.",
                                    fix_snippet="# nginx\nserver_tokens off;\n# apache\nServerTokens Prod\nServerSignature Off\n# php.ini\nexpose_php = Off",
                                    discriminator=hdr)
            raw = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
            for c in raw or []:
                low, name = c.lower(), c.split("=", 1)[0]
                bad = [f for f, ok in (("Secure", "secure" in low), ("HttpOnly", "httponly" in low),
                                       ("SameSite", "samesite" in low)) if not ok]
                if bad:
                    ctx.add_finding(rule="headers.cookie_flags", module=self.name, severity="medium", asset=ident,
                                    title="Cookie missing security flags", evidence=f"{name}: missing {', '.join(bad)}",
                                    remediation="Set Secure, HttpOnly and SameSite on session cookies.",
                                    fix_snippet="Set-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=Lax",
                                    discriminator=name)
