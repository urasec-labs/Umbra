"""Persistent asset/finding inventory with diffing, baseline approval and suppression."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import Asset, Finding, now_iso


class Inventory:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data: dict = {"assets": {}, "findings": {}, "approved": {}, "suppressed": {}, "runs": []}
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                pass

    # -- state ---------------------------------------------------------
    @property
    def is_empty(self) -> bool:
        return not self.data["assets"] and not self.data["runs"]

    @property
    def approved(self) -> set[str]:
        return set(self.data["approved"])

    @property
    def suppressed(self) -> dict:
        return self.data["suppressed"]

    def approve(self, keys: list[str], note: str = "") -> int:
        for k in keys:
            self.data["approved"][k] = {"at": now_iso(), "note": note}
        return len(keys)

    def approve_all_known(self, note: str = "") -> int:
        return self.approve(list(self.data["assets"]), note)

    def revoke(self, key: str) -> bool:
        return self.data["approved"].pop(key, None) is not None

    def suppress(self, fingerprint: str, reason: str) -> None:
        self.data["suppressed"][fingerprint] = {"reason": reason, "at": now_iso()}

    def unsuppress(self, fingerprint: str) -> bool:
        return self.data["suppressed"].pop(fingerprint, None) is not None

    # -- diffing -------------------------------------------------------
    def update_assets(self, current: dict[str, Asset], kinds_scanned: set[str]):
        ts, prev = now_iso(), self.data["assets"]
        new, gone = [], []
        for key, a in current.items():
            if key not in prev:
                new.append(key)
                prev[key] = {"kind": a.kind, "value": a.value, "first_seen": ts}
            prev[key].update(source=a.source, meta=a.meta, last_seen=ts)
        for key, v in list(prev.items()):
            if v["kind"] in kinds_scanned and key not in current:
                gone.append(key)
                del prev[key]
        return new, gone

    def update_findings(self, current: list[Finding], modules_ok: set[str]):
        ts, prev = now_iso(), self.data["findings"]
        cur = {f.fingerprint: f for f in current}
        new = [fp for fp in cur if fp not in prev]
        resolved = []
        for fp, v in list(prev.items()):
            if v["module"] in modules_ok and fp not in cur:
                resolved.append({"fingerprint": fp, **v})
                del prev[fp]
        for fp, f in cur.items():
            prev.setdefault(fp, {"first_seen": ts})
            prev[fp].update(module=f.module, title=f.title, severity=f.severity,
                            asset=f.asset, last_seen=ts)
        return new, resolved

    def record_run(self, summary: dict) -> None:
        self.data["runs"] = (self.data["runs"] + [summary])[-50:]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)
