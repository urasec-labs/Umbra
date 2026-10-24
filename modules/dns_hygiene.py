"""Email-auth and DNS hygiene: SPF, DMARC, CAA, dangling CNAMEs (subdomain takeover risk)."""
from __future__ import annotations

from core.plugin_base import Module
from utils import net

TAKEOVER_HINTS = ("github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com", "azurewebsites.net",
                  "cloudapp.net", "trafficmanager.net", "blob.core.windows.net", "elasticbeanstalk.com",
                  "fastly.net", "ghost.io", "pantheonsite.io", "surge.sh", "netlify.app", "readme.io")


class DnsHygiene(Module):
    name = "dns_hygiene"
    description = "SPF / DMARC / CAA checks and dangling-CNAME detection"
    category = "dns"

    def run(self, ctx):
        t = ctx.cfg.get("scan.timeout", 6)
        for d in ctx.domains:
            spf = [x for x in net.resolve(d, "TXT", t) if x.lower().startswith("v=spf1")]
            if not spf:
                ctx.add_finding(rule="dns.spf_missing", module=self.name, severity="medium", asset=d,
                                title="SPF record missing",
                                description="Without SPF anyone can send mail that appears to come from this domain.",
                                remediation="Publish a TXT record listing the servers allowed to send mail, ending in -all (or ~all while testing).",
                                fix_snippet=f'{d}.  IN TXT  "v=spf1 include:_spf.your-mail-provider.com -all"',
                                references=["RFC 7208"])
            elif any(s.lower().rstrip('"').endswith("+all") or " +all" in s.lower() for s in spf):
                ctx.add_finding(rule="dns.spf_permissive", module=self.name, severity="high", asset=d,
                                title="SPF allows any sender (+all)", evidence=spf[0][:200],
                                remediation="Replace +all with -all (or ~all) and list real senders explicitly.")
            dm = [x for x in net.resolve(f"_dmarc.{d}", "TXT", t) if x.lower().startswith("v=dmarc1")]
            if not dm:
                ctx.add_finding(rule="dns.dmarc_missing", module=self.name, severity="medium", asset=d,
                                title="DMARC record missing",
                                description="DMARC tells receivers what to do with spoofed mail and sends you reports.",
                                remediation="Start with p=none + reporting, then move to quarantine and reject.",
                                fix_snippet=f'_dmarc.{d}.  IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@{d}; adkim=s; aspf=s"',
                                references=["RFC 7489"])
            elif "p=none" in dm[0].replace(" ", "").lower():
                ctx.add_finding(rule="dns.dmarc_monitor_only", module=self.name, severity="low", asset=d,
                                title="DMARC policy is monitor-only (p=none)", evidence=dm[0][:200],
                                remediation="After reviewing aggregate reports, raise the policy to quarantine/reject.")
            if not net.resolve(d, "CAA", t):
                ctx.add_finding(rule="dns.caa_missing", module=self.name, severity="low", asset=d,
                                title="No CAA record",
                                description="CAA restricts which certificate authorities may issue certificates for the domain.",
                                remediation="Add a CAA record for the CA you use.",
                                fix_snippet=f'{d}.  IN CAA  0 issue "letsencrypt.org"')

        for host, target in ctx.cnames.items():
            if not ctx.in_scope(host) or not net.is_nxdomain(target, t):
                continue
            risky = any(target.endswith(h) for h in TAKEOVER_HINTS)
            ctx.add_finding(rule="dns.dangling_cname", module=self.name,
                            severity="high" if risky else "medium", asset=host,
                            title="Dangling CNAME (possible subdomain takeover)",
                            description=f"{host} points to {target}, which does not exist. An attacker could claim the target and serve content on your domain.",
                            evidence=f"{host} CNAME {target}",
                            remediation="Delete the stale DNS record, or re-create the resource it points to.",
                            fix_snippet=f"# remove from your DNS zone:\n{host}.  IN CNAME  {target}.",
                            references=["OWASP: Subdomain Takeover"])
