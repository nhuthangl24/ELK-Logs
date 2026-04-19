from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

from src.utils.common import ensure_directory
from src.utils.serialization import save_json


def evaluate_model(model: Any, features: pd.DataFrame, labels: pd.Series, feature_names: list[str], output_dir: Path) -> dict[str, Any]:
    ensure_directory(output_dir)
    predictions = model.predict(features)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[:, 1]
    else:
        probabilities = predictions.astype(np.float32)

    metrics = {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1_score": float(f1_score(labels, predictions, zero_division=0)),
    }

    matrix = confusion_matrix(labels, predictions).tolist()
    report_text = classification_report(labels, predictions, zero_division=0)
    report_dict = classification_report(labels, predictions, zero_division=0, output_dict=True)

    importance_values = getattr(model, "feature_importances_", np.zeros(len(feature_names), dtype=np.float32))
    feature_importance = (
        pd.DataFrame({"feature": feature_names, "importance": importance_values})
        .sort_values(by="importance", ascending=False)
        .reset_index(drop=True)
    )

    pd.DataFrame(matrix, index=["actual_0", "actual_1"], columns=["pred_0", "pred_1"]).to_csv(output_dir / "confusion_matrix.csv")
    feature_importance.to_csv(output_dir / "feature_importance.csv", index=False)
    (output_dir / "classification_report.txt").write_text(report_text, encoding="utf-8")

    payload = {
        **metrics,
        "confusion_matrix": matrix,
        "classification_report": report_dict,
        "probability_summary": {
            "min": float(np.min(probabilities)),
            "max": float(np.max(probabilities)),
            "mean": float(np.mean(probabilities)),
        },
        "feature_importance_top_25": feature_importance.head(25).to_dict(orient="records"),
    }
    save_json(payload, output_dir / "evaluation.json")
    return payload
