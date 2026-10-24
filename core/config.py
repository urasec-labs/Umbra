"""YAML config loader with deep-merge and dotted-key access."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _merge(base: dict, over: dict) -> dict:
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


class Config:
    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, user_path: str | None = None) -> "Config":
        with open(ROOT / "config" / "default.yaml", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        candidates = [Path(user_path)] if user_path else [ROOT / "config" / "umbra.yaml"]
        for p in candidates:
            if p.exists():
                with open(p, encoding="utf-8") as fh:
                    _merge(data, yaml.safe_load(fh) or {})
            elif user_path:
                raise FileNotFoundError(f"config not found: {p}")
        return cls(data)

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self.data
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    def add_unique(self, dotted: str, values: list) -> None:
        cur = list(self.get(dotted, []) or [])
        for v in values:
            if v not in cur:
                cur.append(v)
        self.set(dotted, cur)

    @property
    def data_dir(self) -> Path:
        p = Path(self.get("app.data_dir", "data"))
        return p if p.is_absolute() else ROOT / p

    def snapshot(self) -> dict:
        return copy.deepcopy(self.data)
