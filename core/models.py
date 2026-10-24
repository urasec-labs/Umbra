"""Data models: Asset, Finding, ScanJob."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = more severe
SEV_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Asset:
    kind: str            # domain | subdomain | host | port | certificate | repo
    value: str
    source: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["key"] = self.key
        return d


@dataclass
class Finding:
    rule: str                      # stable rule id, e.g. "headers.missing"
    module: str
    title: str
    severity: str
    asset: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""          # human-readable fix steps
    fix_snippet: str = ""          # copy-paste config / command
    references: list[str] = field(default_factory=list)
    discriminator: str = ""        # makes fingerprint unique per asset+detail

    def __post_init__(self):
        if self.severity not in SEV_RANK:
            raise ValueError(f"invalid severity: {self.severity}")

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule}|{self.asset}|{self.discriminator}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanJob:
    profile: str
    started: str = field(default_factory=now_iso)
    finished: str = ""
    scope: dict[str, Any] = field(default_factory=dict)
    modules_run: list[dict] = field(default_factory=list)   # name/status/seconds/error
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    diff: dict[str, Any] = field(default_factory=dict)
    first_run: bool = False
    tool_status: dict[str, bool] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def score(self) -> int:
        penalty = sum(SEV_WEIGHT[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    def grade(self) -> str:
        s = self.score()
        for limit, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
            if s >= limit:
                return g
        return "F"
