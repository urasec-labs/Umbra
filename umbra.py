#!/usr/bin/env python3
"""Umbra — defensive attack-surface monitor with remediation-first reporting.
Author: Uras AKAS | urasakas.com
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import __version__                                  # noqa: E402
from core.config import ROOT, Config                          # noqa: E402
from core.inventory import Inventory                          # noqa: E402
from core.models import SEV_RANK, SEVERITIES                  # noqa: E402
from core import notifier                                     # noqa: E402
from core.orchestrator import inventory_path, load_modules, run_scan  # noqa: E402
from utils import net                                         # noqa: E402

BANNER = r"""
  _   _                 _
 | | | |_ __ ___  | |__  _ __ __ _
 | | | | '_ ` _ \ | '_ \| '__/ _` |
 | |_| | | | | | || |_) | | | (_| |
  \___/|_| |_| |_||_.__/|_|  \__,_|   defensive attack-surface monitor v%s
""" % __version__


def scope_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="path to a YAML config (default: config/umbra.yaml)")
    p.add_argument("-d", "--domain", action="append", default=[], help="domain you own (repeatable)")
    p.add_argument("--host", action="append", default=[], help="host/IP you own (repeatable)")
    p.add_argument("--path", action="append", default=[], help="local dir/repo to scan for secrets (repeatable)")
    p.add_argument("--exclude", action="append", default=[], help="host/IP that must never be touched")


def load_cfg(a) -> Config:
    cfg = Config.load(getattr(a, "config", None))
    cfg.add_unique("scope.domains", getattr(a, "domain", []) or [])
    cfg.add_unique("scope.hosts", getattr(a, "host", []) or [])
    cfg.add_unique("scope.paths", getattr(a, "path", []) or [])
    cfg.add_unique("scope.exclude", getattr(a, "exclude", []) or [])
    return cfg


def print_summary(job, paths, alert, sent) -> None:
    c = job.counts()
    print(f"\n── Grade {job.grade()} · score {job.score()}/100 · "
          + " ".join(f"{s}:{c[s]}" for s in SEVERITIES))
    d = job.diff
    if job.first_run:
        print("   First run: baseline created (no change alerts).")
    else:
        print(f"   new assets {len(d['new_assets'])} · gone {len(d['gone_assets'])} · "
              f"new findings {len(d['new_findings'])} · resolved {len(d['resolved_findings'])}")
    for f in job.findings[:8]:
        print(f"   [{f.severity.upper():8}] {f.title} — {f.asset}  ({f.fingerprint})")
    if len(job.findings) > 8:
        print(f"   … +{len(job.findings) - 8} more in the report")
    for m in job.modules_run:
        if m["status"] != "ok":
            print(f"   ! module {m['name']} failed: {m['error']}")
    for k, v in paths.items():
        print(f"   {k.upper():10} {v}")
    if alert:
        print(f"   alerts: {sent}")


def cmd_scan(a) -> int:
    cfg = load_cfg(a)
    try:
        job, paths, alert, sent = run_scan(
            cfg, profile=a.profile, module_names=a.modules.split(",") if a.modules else None,
            notify=not a.no_notify, formats=a.format.split(",") if a.format else None,
            out_dir=Path(a.out) if a.out else None, dry_notify=a.dry_notify,
            safe=False if a.no_safe else None)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print_summary(job, paths, alert, sent)
    if a.fail_on and any(SEV_RANK[f.severity] <= SEV_RANK[a.fail_on] for f in job.findings):
        return 2
    return 0


def cmd_monitor(a) -> int:
    cfg = load_cfg(a)
    print(f"Monitoring every {a.interval}s — Ctrl+C to stop.")
    while True:
        try:
            job, paths, alert, sent = run_scan(cfg, profile="monitor", notify=not a.no_notify,
                                               formats=["json", "html"], dry_notify=a.dry_notify)
            print_summary(job, paths, alert, sent)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        except Exception as e:  # keep the watcher alive
            logging.getLogger("umbra").error("scan failed: %s", e)
        try:
            time.sleep(a.interval)
        except KeyboardInterrupt:
            return 0


def cmd_modules(a) -> int:
    for name, m in sorted(load_modules(Config.load(getattr(a, "config", None))).items()):
        tools = ",".join(m.requires_tools)
        print(f"{name:12} [{m.category:9}] {m.description}" + (f"   (tools: {tools})" if tools else ""))
    return 0


def cmd_tools(a) -> int:
    for t, ok in net.tool_status().items():
        print(f"{t:12} {'available' if ok else 'missing (optional)'}")
    return 0


def cmd_baseline(a) -> int:
    cfg = load_cfg(a)
    inv = Inventory(inventory_path(cfg))
    if a.action == "accept":
        n = inv.approve(a.key, a.note) if a.key else inv.approve_all_known(a.note)
        inv.save()
        print(f"approved {n} asset(s). Findings tied to them will no longer be raised.")
    elif a.action == "revoke":
        for k in a.key:
            print(f"{'revoked' if inv.revoke(k) else 'not found'}: {k}")
        inv.save()
    else:
        for k, v in inv.data["approved"].items():
            print(f"{k}  ({v['at']}) {v.get('note', '')}")
        print(f"{len(inv.data['approved'])} approved, {len(inv.data['assets'])} tracked assets.")
    return 0


def cmd_suppress(a) -> int:
    inv = Inventory(inventory_path(load_cfg(a)))
    if a.undo:
        print("restored" if inv.unsuppress(a.fingerprint) else "not found")
    else:
        inv.suppress(a.fingerprint, a.reason)
        print(f"suppressed {a.fingerprint}: {a.reason}")
    inv.save()
    return 0


def cmd_notify_test(a) -> int:
    cfg = load_cfg(a)
    chs = list(notifier.channels(cfg))
    print("configured channels:", ", ".join(chs) or "none")
    print(notifier.send_all(cfg, "🌑 Umbra test alert — notifications are working.", dry_run=a.dry_run))
    return 0


def cmd_init(a) -> int:
    dst = ROOT / "config" / "umbra.yaml"
    if dst.exists():
        print(f"{dst} already exists.")
        return 1
    dst.write_text("# Umbra overrides — only list what differs from default.yaml\n"
                   "scope:\n  domains: []   # e.g. [example.com]\n  hosts: []\n  paths: []\n  exclude: []\n"
                   "policy:\n  allowed_ports: [80, 443]\nnotifications:\n  min_severity: medium\n"
                   "  slack_webhook: \"\"\n  discord_webhook: \"\"\n  telegram_bot_token: \"\"\n  telegram_chat_id: \"\"\n",
                   encoding="utf-8")
    print(f"created {dst}")
    return 0


def cmd_dashboard(a) -> int:
    import dashboard
    return dashboard.serve(load_cfg(a), a.port)


def ask(prompt: str, default: str = "") -> str:
    v = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return v or default


def interactive() -> int:
    print(BANNER)
    print("Yalnızca sahibi olduğunuz veya izinli olduğunuz varlıkları tarayın.\n")
    while True:
        print("Ana Menü\n\n 1  Hızlı Denetim        (quick)\n 2  Tam Denetim          (full)\n"
              " 3  Sürekli İzleme       (monitor)\n 4  Modülleri Listele\n 5  Dış Araç Durumu\n"
              " 6  Baseline Onayla (kabul edilen riskler)\n 7  Web Dashboard\n 8  Bildirim Testi\n 0  Çıkış\n")
        c = ask("Seçim")
        ns = argparse.Namespace(config=None, domain=[], host=[], path=[], exclude=[], profile="quick",
                                modules=None, no_notify=False, dry_notify=False, format=None, out=None,
                                no_safe=False, fail_on=None, interval=3600, key=[], note="", action="accept",
                                dry_run=False, port=8788)
        if c == "0":
            return 0
        if c in {"1", "2", "3", "6"}:
            ns.domain = [x for x in ask("Domain(ler) (virgülle, boş bırakılabilir)").replace(" ", "").split(",") if x]
            ns.host = [x for x in ask("Host/IP(ler) (virgülle, boş bırakılabilir)").replace(" ", "").split(",") if x]
            ns.path = [x for x in ask("Kod dizini (secret taraması için, boş bırakılabilir)").split(",") if x]
        try:
            if c in {"1", "2"}:
                ns.profile = "quick" if c == "1" else "full"
                cmd_scan(ns)
            elif c == "3":
                cmd_monitor(ns)
            elif c == "4":
                cmd_modules(ns)
            elif c == "5":
                cmd_tools(ns)
            elif c == "6":
                cmd_baseline(ns)
            elif c == "7":
                cmd_dashboard(ns)
            elif c == "8":
                cmd_notify_test(ns)
        except KeyboardInterrupt:
            print()
        print()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="umbra", description="Umbra — defensive attack-surface monitor")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="run a scan and generate reports")
    scope_args(s)
    s.add_argument("-p", "--profile", default="quick", help="quick | full | monitor | code (see config)")
    s.add_argument("-m", "--modules", help="comma-separated modules (overrides profile)")
    s.add_argument("--format", help="html,pdf,json")
    s.add_argument("--out", help="report output directory")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--dry-notify", action="store_true", help="build alerts but do not send")
    s.add_argument("--no-safe", action="store_true", help="disable safe mode (only on assets you own)")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 2 if findings at/above this severity (for CI)")
    s.set_defaults(fn=cmd_scan)

    m = sub.add_parser("monitor", help="repeat scans and alert on changes")
    scope_args(m)
    m.add_argument("--interval", type=int, default=3600, help="seconds between scans")
    m.add_argument("--no-notify", action="store_true")
    m.add_argument("--dry-notify", action="store_true")
    m.set_defaults(fn=cmd_monitor)

    for name, fn, h in (("modules", cmd_modules, "list modules"), ("tools", cmd_tools, "external tool status")):
        x = sub.add_parser(name, help=h)
        x.add_argument("--config")
        x.set_defaults(fn=fn)

    b = sub.add_parser("baseline", help="accept/revoke/list known-good assets")
    scope_args(b)
    b.add_argument("action", choices=["accept", "revoke", "list"])
    b.add_argument("--key", action="append", default=[], help="asset key, e.g. port:203.0.113.5:8080")
    b.add_argument("--note", default="")
    b.set_defaults(fn=cmd_baseline)

    sp = sub.add_parser("suppress", help="hide a finding by fingerprint (accepted risk / false positive)")
    scope_args(sp)
    sp.add_argument("fingerprint")
    sp.add_argument("--reason", default="accepted")
    sp.add_argument("--undo", action="store_true")
    sp.set_defaults(fn=cmd_suppress)

    n = sub.add_parser("notify-test", help="send a test alert")
    scope_args(n)
    n.add_argument("--dry-run", action="store_true")
    n.set_defaults(fn=cmd_notify_test)

    sub.add_parser("init", help="create config/umbra.yaml").set_defaults(fn=cmd_init)

    d = sub.add_parser("dashboard", help="local report dashboard (127.0.0.1)")
    scope_args(d)
    d.add_argument("--port", type=int, default=8788)
    d.set_defaults(fn=cmd_dashboard)
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(message)s")
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    if not a.cmd:
        return interactive() if sys.stdin.isatty() else (ap.print_help() or 0)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
