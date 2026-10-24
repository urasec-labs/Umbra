"""Module (plugin) interface and scan context."""
from __future__ import annotations

import logging
from typing import Iterable

from .models import Asset, Finding

WEB_PORTS = {80: "http", 443: "https", 8000: "http", 8008: "http", 8080: "http",
             8081: "http", 8443: "https", 8888: "http", 3000: "http", 5000: "http"}


class ScanContext:
    """Shared state passed to every module during a scan."""

    def __init__(self, cfg, log: logging.Logger, approved: set[str] | None = None,
                 safe: bool = True):
        self.cfg = cfg
        self.log = log
        self.safe = safe
        self.approved = approved or set()
        self.assets: dict[str, Asset] = {}
        self.findings: list[Finding] = []
        self.resolved: dict[str, list[str]] = {}   # hostname -> [ip, ...]
        self.cnames: dict[str, str] = {}           # hostname -> cname target
        self.ports_scanned = False
        self.tool_status: dict[str, bool] = {}

    # -- scope helpers -------------------------------------------------
    @property
    def domains(self) -> list[str]:
        return [d.lower().strip(".") for d in self.cfg.get("scope.domains", [])]

    @property
    def hosts(self) -> list[str]:
        return [h.strip() for h in self.cfg.get("scope.hosts", [])]

    @property
    def paths(self) -> list[str]:
        return [str(p) for p in self.cfg.get("scope.paths", [])]

    @property
    def excluded(self) -> set[str]:
        return {str(x).lower() for x in self.cfg.get("scope.exclude", [])}

    def in_scope(self, name: str) -> bool:
        name = name.lower().strip(".")
        if name in self.excluded:
            return False
        if name in {h.lower() for h in self.hosts}:
            return True
        return any(name == d or name.endswith("." + d) for d in self.domains)

    # -- collection helpers --------------------------------------------
    def add_asset(self, kind: str, value: str, source: str = "", **meta) -> Asset:
        a = Asset(kind, value, source, meta)
        existing = self.assets.get(a.key)
        if existing:
            existing.meta.update(meta)
            return existing
        self.assets[a.key] = a
        return a

    def add_finding(self, **kw) -> Finding | None:
        """Record a finding unless the asset was approved in the baseline."""
        f = Finding(**kw)
        if f.asset in self.approved:
            return None
        if all(x.fingerprint != f.fingerprint for x in self.findings):
            self.findings.append(f)
        return f

    def is_approved(self, asset_key: str) -> bool:
        return asset_key in self.approved

    def live_hosts(self) -> list[str]:
        """Hostnames that resolved (plus literal hosts/IPs from scope.hosts)."""
        out = [h for h in self.resolved if self.resolved[h]]
        for h in self.hosts:
            if h not in out and h.lower() not in self.excluded:
                out.append(h)
        return sorted(set(out))

    def ip_hosts(self) -> dict[str, list[str]]:
        m: dict[str, list[str]] = {}
        for h, ips in self.resolved.items():
            for ip in ips:
                m.setdefault(ip, []).append(h)
        return m

    def web_endpoints(self) -> list[tuple[str, str, int]]:
        """(host, scheme, port) tuples worth probing over HTTP(S)."""
        eps: set[tuple[str, str, int]] = set()
        if not self.ports_scanned:
            for h in self.live_hosts():
                eps.add((h, "https", 443))
                eps.add((h, "http", 80))
            return sorted(eps)
        ip_to_hosts = self.ip_hosts()
        for a in self.assets.values():
            if a.kind != "port":
                continue
            ip, port = a.meta["ip"], a.meta["port"]
            if port in WEB_PORTS:
                for h in ip_to_hosts.get(ip, [ip]):
                    eps.add((h, WEB_PORTS[port], port))
        return sorted(eps)


class Module:
    """Base class for all analysis modules. Drop a subclass in modules/."""
    name = "base"
    description = ""
    category = "general"
    produces: Iterable[str] = ()           # asset kinds this module owns
    requires_tools: Iterable[str] = ()     # optional external binaries

    def run(self, ctx: ScanContext) -> None:  # pragma: no cover
        raise NotImplementedError
