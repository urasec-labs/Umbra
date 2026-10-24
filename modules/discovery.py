"""Inventory your own external attack surface: subdomains via CT logs, wordlist, subfinder."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import requests

from core.plugin_base import Module
from utils import net

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


class Discovery(Module):
    name = "discovery"
    description = "Enumerate and resolve your own domains/subdomains (crt.sh, wordlist, subfinder)"
    category = "inventory"
    produces = ("domain", "subdomain", "host")

    def run(self, ctx):
        timeout = ctx.cfg.get("scan.timeout", 6)
        candidates: dict[str, str] = {}   # name -> source
        for d in ctx.domains:
            ctx.add_asset("domain", d, "scope")
            candidates[d] = "scope"
            if ctx.cfg.get("scan.use_crtsh", True):
                for n in self._crtsh(d, timeout, ctx):
                    candidates.setdefault(n, "crt.sh")
            if net.have("subfinder"):
                rc, out, _ = net.run_cmd(["subfinder", "-d", d, "-silent"], timeout=180)
                for n in out.split():
                    n = n.strip().lower()
                    if rc == 0 and _HOST_RE.match(n) and ctx.in_scope(n):
                        candidates.setdefault(n, "subfinder")
            for w in ctx.cfg.get("scan.wordlist", []):
                candidates.setdefault(f"{w}.{d}", "wordlist")

        for h in ctx.hosts:
            candidates.setdefault(h, "scope")

        names = [n for n in candidates if ctx.in_scope(n)]
        with ThreadPoolExecutor(max_workers=ctx.cfg.get("scan.threads", 32)) as ex:
            results = list(ex.map(lambda n: (n, net.resolve(n, "A", timeout),
                                             net.resolve(n, "CNAME", timeout) if not net.is_ip(n) else []),
                                  names))
        for name, ips, cnames in results:
            src = candidates[name]
            if cnames:
                ctx.cnames[name] = cnames[0].rstrip(".").lower()
            if not ips and src in ("wordlist", "crt.sh") and not cnames:
                continue                       # guessed/historic name that does not exist (anymore)
            if ips:
                ctx.resolved[name] = ips
            if name in ctx.domains:
                ctx.assets[f"domain:{name}"].meta.update(ips=ips)
            elif net.is_ip(name) or name in ctx.hosts:
                ctx.add_asset("host", name, src, ips=ips)
            else:
                ctx.add_asset("subdomain", name, src, ips=ips, cname=ctx.cnames.get(name, ""))
        ctx.log.info("discovery: %d names, %d resolved", len(names), len(ctx.resolved))

    @staticmethod
    def _crtsh(domain: str, timeout: float, ctx) -> set[str]:
        try:
            r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                             timeout=max(timeout, 20), headers={"User-Agent": ctx.cfg.get("scan.user_agent")})
            r.raise_for_status()
            names = set()
            for row in r.json():
                for n in str(row.get("name_value", "")).splitlines():
                    n = n.strip().lower().lstrip("*.")
                    if _HOST_RE.match(n):
                        names.add(n)
            return names
        except (requests.RequestException, ValueError) as e:
            ctx.log.warning("crt.sh unavailable for %s (%s) — continuing with other sources", domain, type(e).__name__)
            return set()
