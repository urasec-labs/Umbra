"""Wrappers for defensive tools: gitleaks, trivy, pip-audit, lynis. Missing tools are skipped."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from core.plugin_base import Module
from utils import net

SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}
MAX_PER_TOOL = 200


class ExtTools(Module):
    name = "ext_tools"
    description = "Run gitleaks / trivy / pip-audit on scope.paths and lynis on this host (if installed)"
    category = "code"
    requires_tools = ("gitleaks", "trivy", "pip-audit", "lynis")

    def run(self, ctx):
        for p in ctx.paths:
            rp = Path(p).expanduser().resolve()
            if not rp.exists():
                continue
            self.gitleaks(ctx, rp)
            self.trivy(ctx, rp)
            self.pip_audit(ctx, rp)
        if ctx.cfg.get("scope.local_audit", False):
            self.lynis(ctx)

    # ---- gitleaks ------------------------------------------------------
    def gitleaks(self, ctx, rp: Path):
        if not net.have("gitleaks"):
            return ctx.log.info("ext_tools: gitleaks not installed — skipped")
        with tempfile.TemporaryDirectory() as td:
            rep = os.path.join(td, "r.json")
            net.run_cmd(["gitleaks", "detect", "--source", str(rp), "--report-format", "json", "--report-path", rep,
                         "--redact", "--no-banner", "--exit-code", "0"], timeout=600)
            try:
                items = json.loads(Path(rep).read_text() or "[]")
            except (OSError, json.JSONDecodeError):
                return
        for it in items[:MAX_PER_TOOL]:
            f = it.get("File", "?")
            ctx.add_finding(rule="secrets.gitleaks", module=self.name, severity="high",
                            asset=f"{rp.name}/{f}", title=f"Secret detected by gitleaks: {it.get('RuleID', '?')}",
                            evidence=f"line {it.get('StartLine')}, commit {str(it.get('Commit', ''))[:8] or 'working tree'}",
                            description=it.get("Description", ""),
                            remediation="Rotate the credential, remove it from code, and purge it from git history.",
                            fix_snippet="git filter-repo --replace-text <(echo 'LEAKED_VALUE==>REMOVED')\n# then force-push and rotate the secret at its provider",
                            discriminator=f"{it.get('RuleID')}:{it.get('Commit', '')[:8]}:{it.get('StartLine')}")

    # ---- trivy ---------------------------------------------------------
    def trivy(self, ctx, rp: Path):
        if not net.have("trivy"):
            return ctx.log.info("ext_tools: trivy not installed — skipped")
        rc, out, _ = net.run_cmd(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig",
                                  "--severity", "CRITICAL,HIGH,MEDIUM", str(rp)], timeout=900)
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return
        n = 0
        for res in data.get("Results", []) or []:
            target = res.get("Target", "?")
            for v in res.get("Vulnerabilities", []) or []:
                if n >= MAX_PER_TOOL:
                    return
                n += 1
                fixed = v.get("FixedVersion") or ""
                ctx.add_finding(rule="deps.vulnerable", module=self.name, severity=SEV.get(v.get("Severity", ""), "low"),
                                asset=f"{rp.name}/{target}:{v.get('PkgName')}",
                                title=f"Vulnerable dependency: {v.get('PkgName')} ({v.get('VulnerabilityID')})",
                                evidence=f"installed {v.get('InstalledVersion')}" + (f", fixed in {fixed}" if fixed else ", no fix yet"),
                                description=(v.get("Title") or "")[:300],
                                remediation=f"Upgrade {v.get('PkgName')} to {fixed}." if fixed else "No patched release yet: mitigate, pin, or replace the package.",
                                fix_snippet=f"# pip\npip install -U '{v.get('PkgName')}>={fixed}'\n# npm\nnpm install {v.get('PkgName')}@{fixed}" if fixed else "",
                                discriminator=str(v.get("VulnerabilityID")), references=[v.get("PrimaryURL", "")] if v.get("PrimaryURL") else [])
            for m in res.get("Misconfigurations", []) or []:
                if n >= MAX_PER_TOOL:
                    return
                n += 1
                ctx.add_finding(rule="config.misconfig", module=self.name, severity=SEV.get(m.get("Severity", ""), "low"),
                                asset=f"{rp.name}/{target}", title=f"Misconfiguration: {m.get('Title')}",
                                evidence=(m.get("Message") or "")[:200], remediation=(m.get("Resolution") or "")[:300],
                                discriminator=str(m.get("ID")))

    # ---- pip-audit -----------------------------------------------------
    def pip_audit(self, ctx, rp: Path):
        if not net.have("pip-audit"):
            return ctx.log.info("ext_tools: pip-audit not installed — skipped")
        ignore = set(ctx.cfg.get("scan.secret_ignore", []))
        files: list[Path] = []
        if rp.is_file():
            files = [rp]
        else:
            for d, dns, fns in os.walk(rp):
                dns[:] = [x for x in dns if x not in ignore]
                files += [Path(d) / f for f in fns if f.startswith("requirements") and f.endswith(".txt")]
        for req in files[:10]:
            rc, out, _ = net.run_cmd(["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"], timeout=600)
            try:
                deps = json.loads(out or "{}").get("dependencies", [])
            except json.JSONDecodeError:
                continue
            for d in deps:
                for v in d.get("vulns", []):
                    fix = ", ".join(v.get("fix_versions", []))
                    ctx.add_finding(rule="deps.vulnerable", module=self.name, severity="medium",
                                    asset=f"{rp.name}/{req.name}:{d['name']}",
                                    title=f"Vulnerable dependency: {d['name']} ({v.get('id')})",
                                    evidence=f"installed {d.get('version')}" + (f", fixed in {fix}" if fix else ""),
                                    description=(v.get("description") or "")[:300],
                                    remediation=f"Upgrade {d['name']} to {fix}." if fix else "No fix released yet.",
                                    fix_snippet=f"pip install -U '{d['name']}>={v['fix_versions'][0]}'" if v.get("fix_versions") else "",
                                    discriminator=str(v.get("id")))

    # ---- lynis ---------------------------------------------------------
    def lynis(self, ctx):
        if not net.have("lynis"):
            return ctx.log.info("ext_tools: lynis not installed — skipped")
        net.run_cmd(["lynis", "audit", "system", "--quick", "--no-colors", "--quiet"], timeout=900)
        for rp in ("/var/log/lynis-report.dat", os.path.expanduser("~/lynis-report.dat")):
            if os.path.exists(rp):
                break
        else:
            return ctx.log.warning("ext_tools: lynis report not found (run as root?)")
        for line in Path(rp).read_text(errors="replace").splitlines():
            for key, sev in (("warning[]=", "medium"), ("suggestion[]=", "low")):
                if line.startswith(key):
                    parts = line[len(key):].split("|")
                    tid, text = parts[0], (parts[1] if len(parts) > 1 else "")
                    ctx.add_finding(rule=f"hardening.lynis.{tid}", module=self.name, severity=sev, asset="localhost",
                                    title=f"Hardening: {text[:90]}", evidence=f"lynis test {tid}",
                                    remediation="See `lynis show details " + tid + "` for the exact fix.",
                                    fix_snippet=f"sudo lynis show details {tid}", discriminator=tid)
