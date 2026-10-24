"""Find leaked credentials in your own repos/directories (values are always redacted)."""
from __future__ import annotations

import math
import os
import re
from pathlib import Path

from core.plugin_base import Module
from utils import net

PATTERNS = [
    ("aws_access_key", "AWS access key ID", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key", "Private key block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", "GitHub token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", "Slack token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", "Slack webhook URL", "high", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("discord_webhook", "Discord webhook URL", "high", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")),
    ("telegram_bot", "Telegram bot token", "high", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("google_api_key", "Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_live", "Stripe live secret key", "critical", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("generic_secret", "Hard-coded credential", "medium",
     re.compile(r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]""")),
]
PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]|<.+>|xxx+|\*{3,}|dummy|sample|placeholder|\$\{|\{\{|test)")
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".so", ".exe", ".dll", ".bin",
              ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".pyc", ".class", ".jar", ".lock"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s)))


def redact(v: str) -> str:
    return v[:4] + "…" + "*" * 4 if len(v) > 8 else "****"


def scan_text(text: str):
    """Yield (line_no, rule_id, label, severity, redacted) for each hit."""
    for no, line in enumerate(text.splitlines(), 1):
        if "umbra:ignore" in line or len(line) > 2000:
            continue
        for rid, label, sev, rx in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            val = m.group(1) if rx.groups else m.group(0)
            if rid == "generic_secret" and (PLACEHOLDER.search(val) or _entropy(val) < 3.0):
                continue
            if rid != "private_key" and PLACEHOLDER.search(val) and rid != "generic_secret":
                continue
            yield no, rid, label, sev, redact(val) if rid != "private_key" else "BEGIN … PRIVATE KEY"
            break


class Secrets(Module):
    name = "secrets"
    description = "Detect hard-coded secrets and tracked .env files in scope.paths"
    category = "code"

    def run(self, ctx):
        ignore = set(ctx.cfg.get("scan.secret_ignore", []))
        limit = ctx.cfg.get("scan.secret_max_bytes", 1_000_000)
        for root in ctx.paths:
            rp = Path(root).expanduser().resolve()
            if not rp.exists():
                ctx.log.warning("secrets: path not found: %s", root)
                continue
            ctx.add_asset("repo", str(rp.resolve()), "scope")
            if (rp / ".git").exists() and net.have("git"):
                rc, out, _ = net.run_cmd(["git", "-C", str(rp), "ls-files"], timeout=60)
                for f in out.splitlines() if rc == 0 else []:
                    if Path(f).name.startswith(".env") and not f.endswith((".example", ".sample", ".template")):
                        ctx.add_finding(rule="secrets.env_tracked", module=self.name, severity="high", asset=f"{rp.name}/{f}",
                                        title=".env file is tracked by git", evidence=f,
                                        remediation="Untrack the file, add it to .gitignore, and rotate every secret it contained (history keeps old copies).",
                                        fix_snippet=f"git rm --cached {f}\necho '{Path(f).name}' >> .gitignore\ngit commit -m 'stop tracking env file'\n# purge history: git filter-repo --path {f} --invert-paths",
                                        discriminator=f)
            files = [rp] if rp.is_file() else self._walk(rp, ignore)
            for fp in files:
                try:
                    if fp.suffix.lower() in BINARY_EXT or fp.stat().st_size > limit:
                        continue
                    text = fp.read_bytes().decode("utf-8", "replace")
                except OSError:
                    continue
                if "\x00" in text[:1024]:
                    continue
                for no, rid, label, sev, red in scan_text(text):
                    rel = f"{rp.name}/{fp.relative_to(rp)}" if rp.is_dir() else fp.name
                    ctx.add_finding(
                        rule=f"secrets.{rid}", module=self.name, severity=sev, asset=rel, title=f"{label} in source",
                        evidence=f"{red} (line {no})",
                        description="Credentials in code end up in git history, CI logs, backups and screenshots.",
                        remediation="Revoke/rotate the credential first, then move it to a secret manager or environment variable and add a pre-commit scanner.",
                        fix_snippet=("# 1. rotate the secret at the provider\n# 2. load it from the environment instead\nimport os\nTOKEN = os.environ['SERVICE_TOKEN']\n"
                                     "# 3. block future leaks\npip install pre-commit  # then add gitleaks hook to .pre-commit-config.yaml"),
                        discriminator=f"{rid}:{red}", references=["OWASP A07: Identification and Authentication Failures"])

    @staticmethod
    def _walk(root: Path, ignore: set[str]):
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in ignore]
            for f in fns:
                yield Path(dp) / f
