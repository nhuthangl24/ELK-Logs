from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "artifacts_dir": "artifacts",
    "data_search_roots": ["..", "."],
    "loader": {
        "csv_chunksize": 250000,
        "modsec_batch_size": 50000,
        "cic_encodings": ["utf-8", "latin1", "cp1252"],
    },
    "split": {
        "test_size": 0.15,
        "validation_size": 0.15,
    },
    "model_selection": {
        "metric": "f1",
        "max_selection_rows": 250000,
    },
    "feature_builder": {
        "hash_bucket_size": 4096,
    },
    "xgboost": {
        "n_estimators": 400,
        "max_depth": 10,
        "learning_rate": 0.03,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "n_jobs": -1,
        "random_state": 42,
        "tree_method": "hist",
        "eval_metric": "logloss",
        "objective": "binary:logistic",
    },
    "random_forest": {
        "n_estimators": 300,
        "max_depth": 18,
        "min_samples_leaf": 2,
        "n_jobs": -1,
        "random_state": 42,
        "class_weight": "balanced_subsample",
    },
    "runtime": {
        "random_state": 42,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _resolve_paths(project_root: Path, config: dict[str, Any]) -> dict[str, Any]:
    config = copy.deepcopy(config)
    config["project_root"] = str(project_root)
    config["artifacts_dir"] = str((project_root / config["artifacts_dir"]).resolve())
    config["data_search_roots"] = [
        str((project_root / relative_root).resolve()) for relative_root in config["data_search_roots"]
    ]
    return config


def load_config(project_root: Path, config_path: str | Path | None = None, data_root: str | Path | None = None, artifacts_dir: str | Path | None = None) -> dict[str, Any]:
    config = copy.deepcopy(DEFAULT_CONFIG)

    if config_path is not None:
        resolved_config_path = Path(config_path)
        if not resolved_config_path.is_absolute():
            resolved_config_path = project_root / resolved_config_path
        with resolved_config_path.open("r", encoding="utf-8") as handle:
            config = _deep_merge(config, json.load(handle))

    if data_root is not None:
        config["data_search_roots"] = [str(data_root)]

    if artifacts_dir is not None:
        config["artifacts_dir"] = str(artifacts_dir)

    return _resolve_paths(project_root, config)
