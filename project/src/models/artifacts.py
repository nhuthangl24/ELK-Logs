from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from src.utils.common import ensure_directory
from src.utils.serialization import load_json, load_pickle, save_json, save_pickle


def save_training_artifacts(
    artifact_dir: Path,
    model: Any,
    feature_builder: Any,
    feature_list: list[str],
    schema_metadata: dict[str, Any],
    training_summary: dict[str, Any],
    test_dataset: pd.DataFrame,
) -> None:
    ensure_directory(artifact_dir)
    save_pickle(model, artifact_dir / "model.pkl")
    save_pickle(feature_builder, artifact_dir / "feature_builder.pkl")
    save_json(feature_builder.to_encoder_payload(), artifact_dir / "encoders.json")
    save_json(schema_metadata, artifact_dir / "schema_metadata.json")
    save_json(feature_list, artifact_dir / "feature_list.json")
    save_json(training_summary, artifact_dir / "training_summary.json")
    test_dataset.to_parquet(artifact_dir / "test_dataset.parquet", index=False)


def load_runtime_artifacts(artifact_dir: Path) -> dict[str, Any]:
    encoders_path = artifact_dir / "encoders.json"
    schema_metadata_path = artifact_dir / "schema_metadata.json"
    training_summary_path = artifact_dir / "training_summary.json"

    return {
        "model": load_pickle(artifact_dir / "model.pkl"),
        "feature_builder": load_pickle(artifact_dir / "feature_builder.pkl"),
        "feature_list": load_json(artifact_dir / "feature_list.json"),
        "encoders": load_json(encoders_path) if encoders_path.exists() else {},
        "schema_metadata": load_json(schema_metadata_path) if schema_metadata_path.exists() else {},
        "training_summary": load_json(training_summary_path) if training_summary_path.exists() else {},
    }
