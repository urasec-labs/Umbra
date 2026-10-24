"""Alert delivery: Slack, Discord, Telegram, generic webhook."""
from __future__ import annotations

import os

import requests

from .models import SEV_RANK, ScanJob

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _chunks(text: str, limit: int) -> list[str]:
    out, cur = [], ""
    for line in text.splitlines(keepends=True):
        if len(cur) + len(line) > limit and cur:
            out.append(cur)
            cur = ""
        cur += line[:limit]
    if cur:
        out.append(cur)
    return out or [""]


def channels(cfg) -> dict[str, dict]:
    g = lambda k, env: cfg.get(f"notifications.{k}") or os.environ.get(env, "")
    ch = {
        "slack": {"url": g("slack_webhook", "UMBRA_SLACK_WEBHOOK")},
        "discord": {"url": g("discord_webhook", "UMBRA_DISCORD_WEBHOOK")},
        "telegram": {"token": g("telegram_bot_token", "UMBRA_TELEGRAM_TOKEN"),
                     "chat": str(g("telegram_chat_id", "UMBRA_TELEGRAM_CHAT"))},
        "webhook": {"url": g("webhook", "UMBRA_WEBHOOK")},
    }
    return {k: v for k, v in ch.items() if all(v.values())}


def send_all(cfg, text: str, payload: dict | None = None, dry_run: bool = False) -> dict[str, str]:
    results: dict[str, str] = {}
    chs = channels(cfg)
    if not chs:
        return {"none": "no channel configured"}
    for name, c in chs.items():
        if dry_run:
            results[name] = "dry-run"
            continue
        try:
            if name == "slack":
                for part in _chunks(text, 3000):
                    requests.post(c["url"], json={"text": part}, timeout=10).raise_for_status()
            elif name == "discord":
                for part in _chunks(text, 1900):
                    requests.post(c["url"], json={"content": part}, timeout=10).raise_for_status()
            elif name == "telegram":
                api = f"https://api.telegram.org/bot{c['token']}/sendMessage"
                for part in _chunks(text, 4000):
                    requests.post(api, data={"chat_id": c["chat"], "text": part},
                                  timeout=10).raise_for_status()
            elif name == "webhook":
                requests.post(c["url"], json=payload or {"text": text}, timeout=10).raise_for_status()
            results[name] = "sent"
        except requests.RequestException as e:
            # never leak tokens/URLs in the error text
            results[name] = f"failed ({type(e).__name__})"
    return results


def build_alert(job: ScanJob, cfg, limit: int = 15) -> str | None:
    """Compose an alert for what CHANGED in this run. None when nothing noteworthy."""
    min_rank = SEV_RANK.get(cfg.get("notifications.min_severity", "medium"), 2)
    d = job.diff
    new_f = [f for f in job.findings
             if f.fingerprint in set(d.get("new_findings", [])) and SEV_RANK[f.severity] <= min_rank]
    new_assets = d.get("new_assets", []) if cfg.get("notifications.notify_new_assets", True) else []
    gone = d.get("gone_assets", [])
    resolved = d.get("resolved_findings", []) if cfg.get("notifications.notify_resolved", True) else []
    if job.first_run or not (new_f or new_assets or resolved):
        return None
    scope = ", ".join(job.scope.get("domains", []) + job.scope.get("hosts", []))[:120] or "local"
    lines = [f"🌑 Umbra | {scope} | grade {job.grade()} ({job.score()}/100)"]
    if new_f:
        lines.append(f"\nNew findings ({len(new_f)}):")
        for f in sorted(new_f, key=lambda x: SEV_RANK[x.severity])[:limit]:
            lines.append(f" {ICON[f.severity]} [{f.severity.upper()}] {f.title} — {f.asset}")
        if len(new_f) > limit:
            lines.append(f" … +{len(new_f) - limit} more")
    if new_assets:
        lines.append(f"\nNew assets ({len(new_assets)}):")
        lines += [f" ➕ {k}" for k in new_assets[:limit]]
        if len(new_assets) > limit:
            lines.append(f" … +{len(new_assets) - limit} more")
    if gone:
        lines.append(f"\nDisappeared assets: {len(gone)}")
    if resolved:
        lines.append(f"\nResolved findings ({len(resolved)}):")
        lines += [f" ✅ {r.get('title', r['fingerprint'])} — {r.get('asset', '')}" for r in resolved[:limit]]
    return "\n".join(lines)
