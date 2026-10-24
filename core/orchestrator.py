"""Module loader and scan runner."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import logging
import pkgutil
import re
import time
from pathlib import Path

from .config import ROOT, Config
from .inventory import Inventory
from .models import SEV_RANK, ScanJob, now_iso
from .plugin_base import Module, ScanContext
from . import notifier, report
from utils import net

log = logging.getLogger("umbra")


def _collect(mod) -> dict[str, Module]:
    found = {}
    for _, cls in inspect.getmembers(mod, inspect.isclass):
        if issubclass(cls, Module) and cls is not Module and cls.__module__ == mod.__name__:
            inst = cls()
            found[inst.name] = inst
    return found


def load_modules(cfg: Config) -> dict[str, Module]:
    registry: dict[str, Module] = {}
    import modules as pkg
    for info in pkgutil.iter_modules(pkg.__path__):
        try:
            registry.update(_collect(importlib.import_module(f"modules.{info.name}")))
        except Exception as e:  # a broken module must not take the tool down
            log.warning("module %s failed to load: %s", info.name, e)
    pdir = Path(cfg.get("app.plugins_dir", "plugins"))
    pdir = pdir if pdir.is_absolute() else ROOT / pdir
    if pdir.is_dir():
        for f in sorted(p for p in pdir.glob("*.py") if not p.name.startswith("_")):
            try:
                spec = importlib.util.spec_from_file_location(f"umbra_plugin_{f.stem}", f)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                registry.update(_collect(m))
            except Exception as e:
                log.warning("plugin %s failed to load: %s", f.name, e)
    return registry


def scope_slug(cfg: Config) -> str:
    parts = sorted(map(str, cfg.get("scope.domains", []) + cfg.get("scope.hosts", [])
                       + cfg.get("scope.paths", [])))
    label = re.sub(r"[^a-z0-9]+", "-", (parts[0] if parts else "scope").lower()).strip("-")[:40]
    return f"{label}-{hashlib.sha1('|'.join(parts).encode()).hexdigest()[:6]}"


def inventory_path(cfg: Config) -> Path:
    return cfg.data_dir / "inventory" / f"{scope_slug(cfg)}.json"


def run_scan(cfg: Config, profile: str = "quick", module_names: list[str] | None = None,
             notify: bool = True, formats: list[str] | None = None,
             out_dir: Path | None = None, dry_notify: bool = False, safe: bool | None = None):
    scope = {"domains": cfg.get("scope.domains", []), "hosts": cfg.get("scope.hosts", []),
             "paths": cfg.get("scope.paths", [])}
    if not any(scope.values()):
        raise ValueError("empty scope: set scope.domains / scope.hosts / scope.paths "
                         "in config or pass --domain/--host/--path")

    registry = load_modules(cfg)
    names = module_names or cfg.get(f"profiles.{profile}")
    if not names:
        raise ValueError(f"unknown profile '{profile}'")
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(unknown)}")

    inv = Inventory(inventory_path(cfg))
    safe = cfg.get("app.safe_mode", True) if safe is None else safe
    ctx = ScanContext(cfg, log, approved=inv.approved, safe=safe)
    job = ScanJob(profile=profile if not module_names else "custom", scope=scope,
                  first_run=inv.is_empty, tool_status=net.tool_status())

    kinds_scanned: set[str] = set()
    modules_ok: set[str] = set()
    for name in names:
        mod = registry[name]
        t0 = time.time()
        entry = {"name": name, "status": "ok", "seconds": 0.0, "error": ""}
        try:
            log.info("▶ %s", name)
            mod.run(ctx)
            kinds_scanned.update(mod.produces)
            modules_ok.add(name)
        except Exception as e:
            entry.update(status="error", error=f"{type(e).__name__}: {e}")
            log.error("module %s failed: %s", name, e)
        entry["seconds"] = round(time.time() - t0, 2)
        job.modules_run.append(entry)

    job.assets = sorted(ctx.assets.values(), key=lambda a: (a.kind, a.value))
    sup = inv.suppressed
    job.findings = sorted((f for f in ctx.findings if f.fingerprint not in sup),
                          key=lambda f: (SEV_RANK[f.severity], f.asset, f.title))
    job.suppressed = [f for f in ctx.findings if f.fingerprint in sup]

    new_assets, gone = inv.update_assets(ctx.assets, kinds_scanned)
    new_f, resolved = inv.update_findings(job.findings, modules_ok)
    job.diff = {"new_assets": new_assets, "gone_assets": gone,
                "new_findings": new_f, "resolved_findings": resolved}
    job.finished = now_iso()
    inv.record_run({"at": job.finished, "profile": job.profile, "score": job.score(),
                    "counts": job.counts(), "new_assets": len(new_assets)})
    inv.save()

    formats = formats or cfg.get("report.formats", ["html", "pdf", "json"])
    out_dir = out_dir or cfg.data_dir / "reports"
    paths = report.generate(job, cfg, Path(out_dir), formats, slug=scope_slug(cfg))

    alert = notifier.build_alert(job, cfg) if notify else None
    sent = notifier.send_all(cfg, alert, dry_run=dry_notify) if alert else {}
    return job, paths, alert, sent
