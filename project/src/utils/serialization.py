from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib

from .common import ensure_directory, json_default


def save_json(data: Any, path: Path) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True, default=json_default)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_pickle(data: Any, path: Path) -> None:
    ensure_directory(path.parent)
    joblib.dump(data, path)


def load_pickle(path: Path) -> Any:
    return joblib.load(path)
