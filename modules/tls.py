"""TLS health: expiry, chain/hostname validity, weak protocol, weak keys."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from core.plugin_base import Module

CERTBOT = "sudo certbot renew --dry-run && sudo certbot renew\n# or request a new cert\nsudo certbot --nginx -d {host}"


def _der_cert(host: str, port: int, timeout: float):
    """Fetch the leaf cert without validating it, plus negotiated protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            return s.getpeercert(binary_form=True), s.version()


def _verify(host: str, port: int, timeout: float) -> str:
    """'' if the chain+hostname validate, else the verifier's message."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return ""
    except ssl.SSLCertVerificationError as e:
        return e.verify_message or str(e)
    except (OSError, ssl.SSLError):
        return ""   # not a verification problem (closed port, protocol error) — handled elsewhere


class Tls(Module):
    name = "tls"
    description = "Certificate expiry/validity and protocol hygiene"
    category = "crypto"
    produces = ("certificate",)

    def run(self, ctx):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            ctx.log.warning("tls: 'cryptography' not installed — skipping")
            return
        timeout = ctx.cfg.get("scan.timeout", 6)
        crit, warn = ctx.cfg.get("policy.cert_critical_days", 7), ctx.cfg.get("policy.cert_warn_days", 30)
        min_tls = ctx.cfg.get("policy.min_tls", "TLSv1.2")
        seen: set[tuple[str, int]] = set()
        for host, scheme, port in ctx.web_endpoints():
            if scheme != "https" or (host, port) in seen:
                continue
            seen.add((host, port))
            ident = f"{host}:{port}"
            try:
                der, version = _der_cert(host, port, timeout)
            except (OSError, ssl.SSLError):
                continue                                     # nothing speaking TLS here
            cert = x509.load_der_x509_certificate(der)
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
            days = (not_after - datetime.now(timezone.utc)).days
            key = cert.public_key()
            bits = getattr(key, "key_size", 0)
            ctx.add_asset("certificate", ident, "tls", host=host, port=port, expires=not_after.date().isoformat(),
                          days_left=days, tls=version, issuer=cert.issuer.rfc4514_string()[:80])

            fix = CERTBOT.format(host=host)
            if days < 0:
                ctx.add_finding(rule="tls.expired", module=self.name, severity="critical", asset=ident,
                                title="TLS certificate has expired", evidence=f"expired {-days} day(s) ago",
                                remediation="Renew the certificate now and automate renewal.", fix_snippet=fix)
            elif days <= crit:
                ctx.add_finding(rule="tls.expiring_soon", module=self.name, severity="high", asset=ident,
                                title=f"TLS certificate expires within {crit} days", evidence=f"{days} day(s) left",
                                remediation="Renew now and set up automatic renewal with monitoring.", fix_snippet=fix)
            elif days <= warn:
                ctx.add_finding(rule="tls.expiring_soon", module=self.name, severity="medium", asset=ident,
                                title=f"TLS certificate expires within {warn} days", evidence=f"{days} day(s) left",
                                remediation="Schedule renewal; verify the auto-renew job is running.", fix_snippet=fix)

            problem = _verify(host, port, timeout)
            if problem and days >= 0:
                low = problem.lower()
                sev = "high" if ("hostname" in low or "self" in low or "unable to get local issuer" in low) else "medium"
                ctx.add_finding(rule="tls.invalid_chain", module=self.name, severity=sev, asset=ident,
                                title="Certificate fails validation", evidence=problem[:160],
                                description="Browsers and API clients will reject this certificate, or users learn to click through warnings.",
                                remediation="Serve a certificate from a trusted CA that covers this hostname, including the full intermediate chain.",
                                fix_snippet=fix)

            order = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
            if version in order and min_tls in order and order.index(version) < order.index(min_tls):
                ctx.add_finding(rule="tls.weak_protocol", module=self.name, severity="high", asset=ident,
                                title=f"Weak TLS protocol negotiated ({version})",
                                remediation=f"Disable protocols older than {min_tls}.",
                                fix_snippet="# nginx\nssl_protocols TLSv1.2 TLSv1.3;\n# apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3")
            if isinstance(key, rsa.RSAPublicKey) and bits < 2048:
                ctx.add_finding(rule="tls.weak_key", module=self.name, severity="high", asset=ident,
                                title=f"Weak RSA key ({bits} bits)", remediation="Reissue with RSA 2048+ or ECDSA P-256.",
                                fix_snippet="openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out csr.pem")
