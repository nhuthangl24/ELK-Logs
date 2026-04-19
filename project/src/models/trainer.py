from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from src.evaluation.metrics import evaluate_model
from src.features.feature_builder import FeatureBuilder

LOGGER = logging.getLogger(__name__)


@dataclass
class TrainingResult:
    model_name: str
    model: Any
    feature_builder: FeatureBuilder
    feature_list: list[str]
    evaluation: dict[str, Any]
    schema_metadata: dict[str, Any]
    training_summary: dict[str, Any]
    test_dataset: pd.DataFrame


class ModelTrainer:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.random_state = int(config["runtime"]["random_state"])
        self.validation_size = float(config["split"]["validation_size"])
        self.test_size = float(config["split"]["test_size"])
        self.selection_limit = int(config["model_selection"]["max_selection_rows"])
        self.hash_bucket_size = int(config["feature_builder"]["hash_bucket_size"])
        self.xgb_config = dict(config["xgboost"])
        self.rf_config = dict(config["random_forest"])

    def train(self, dataset: pd.DataFrame, artifact_dir: Path) -> TrainingResult:
        train_raw, validation_raw, test_raw = self._split_dataframe(dataset)

        selection_builder = FeatureBuilder(hash_bucket_size=self.hash_bucket_size)
        train_features = selection_builder.fit_transform(train_raw)
        validation_features = selection_builder.transform(validation_raw)

        selection_train_features, selection_train_labels, selection_train_weights = self._selection_subset(
            train_features, train_raw["label"], self._sample_weights(train_raw)
        )

        candidate_scores: dict[str, dict[str, float]] = {}
        candidate_models = {
            "xgboost": self._build_xgboost(train_raw["label"]),
            "random_forest": self._build_random_forest(),
        }

        for model_name, model in candidate_models.items():
            LOGGER.info("Training candidate model=%s on %s rows", model_name, len(selection_train_features))
            self._fit_model_with_fallback(model, selection_train_features, selection_train_labels, selection_train_weights)
            validation_predictions = model.predict(validation_features)
            candidate_scores[model_name] = {
                "f1": float(f1_score(validation_raw["label"], validation_predictions, zero_division=0)),
                "accuracy": float(accuracy_score(validation_raw["label"], validation_predictions)),
            }

        selected_model_name = max(candidate_scores, key=lambda name: (candidate_scores[name]["f1"], candidate_scores[name]["accuracy"]))
        LOGGER.info("Selected model=%s scores=%s", selected_model_name, candidate_scores[selected_model_name])

        train_validation_raw = pd.concat([train_raw, validation_raw], ignore_index=True, copy=False)
        final_feature_builder = FeatureBuilder(hash_bucket_size=self.hash_bucket_size)
        final_train_features = final_feature_builder.fit_transform(train_validation_raw)
        final_test_features = final_feature_builder.transform(test_raw)
        final_train_weights = self._sample_weights(train_validation_raw)

        if selected_model_name == "xgboost":
            final_model = self._build_xgboost(train_validation_raw["label"])
        else:
            final_model = self._build_random_forest()

        LOGGER.info("Training final model=%s on %s rows", selected_model_name, len(final_train_features))
        self._fit_model_with_fallback(final_model, final_train_features, train_validation_raw["label"], final_train_weights)

        evaluation = evaluate_model(
            model=final_model,
            features=final_test_features,
            labels=test_raw["label"],
            feature_names=list(final_train_features.columns),
            output_dir=artifact_dir,
        )

        schema_metadata = {
            "unified_schema": [
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "bytes",
                "packets",
                "duration",
                "http_method",
                "uri",
                "label",
            ],
            "source_rows": dataset["source_name"].value_counts().to_dict(),
            "source_label_distribution": dataset.groupby("source_name")["label"].value_counts().unstack(fill_value=0).to_dict(orient="index"),
            "total_rows": int(len(dataset)),
        }

        training_summary = {
            "selected_model": selected_model_name,
            "candidate_scores": candidate_scores,
            "split_rows": {
                "train": int(len(train_raw)),
                "validation": int(len(validation_raw)),
                "test": int(len(test_raw)),
            },
            "class_distribution": dataset["label"].value_counts().to_dict(),
            "feature_count": int(final_train_features.shape[1]),
        }

        return TrainingResult(
            model_name=selected_model_name,
            model=final_model,
            feature_builder=final_feature_builder,
            feature_list=list(final_train_features.columns),
            evaluation=evaluation,
            schema_metadata=schema_metadata,
            training_summary=training_summary,
            test_dataset=test_raw.reset_index(drop=True),
        )

    def _split_dataframe(self, dataset: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        features = dataset.drop(columns=["label"])
        labels = dataset["label"]
        stratify_target = labels if labels.nunique() > 1 else None

        train_validation_features, test_features, train_validation_labels, test_labels = train_test_split(
            features,
            labels,
            test_size=self.test_size,
            random_state=self.random_state,
            shuffle=True,
            stratify=stratify_target,
        )

        validation_fraction_of_remaining = self.validation_size / (1.0 - self.test_size)
        stratify_target = train_validation_labels if train_validation_labels.nunique() > 1 else None
        train_features, validation_features, train_labels, validation_labels = train_test_split(
            train_validation_features,
            train_validation_labels,
            test_size=validation_fraction_of_remaining,
            random_state=self.random_state,
            shuffle=True,
            stratify=stratify_target,
        )

        train_raw = train_features.copy()
        validation_raw = validation_features.copy()
        test_raw = test_features.copy()
        train_raw["label"] = train_labels.to_numpy()
        validation_raw["label"] = validation_labels.to_numpy()
        test_raw["label"] = test_labels.to_numpy()
        return train_raw.reset_index(drop=True), validation_raw.reset_index(drop=True), test_raw.reset_index(drop=True)

    def _selection_subset(self, features: pd.DataFrame, labels: pd.Series, weights: np.ndarray) -> tuple[pd.DataFrame, pd.Series, np.ndarray]:
        if len(features) <= self.selection_limit:
            return features, labels, weights

        indices = np.arange(len(features))
        stratify_target = labels if labels.nunique() > 1 else None
        selection_indices, _ = train_test_split(
            indices,
            train_size=self.selection_limit,
            random_state=self.random_state,
            shuffle=True,
            stratify=stratify_target,
        )
        selection_indices = np.sort(selection_indices)
        return (
            features.iloc[selection_indices].reset_index(drop=True),
            labels.iloc[selection_indices].reset_index(drop=True),
            weights[selection_indices],
        )

    def _sample_weights(self, frame: pd.DataFrame) -> np.ndarray:
        labels = frame["label"].astype(int)
        class_counts = labels.value_counts().to_dict()
        class_weights = {
            class_value: len(labels) / (len(class_counts) * max(class_count, 1))
            for class_value, class_count in class_counts.items()
        }

        source_counts = frame["source_name"].value_counts().to_dict()
        source_weights = {
            source_name: len(frame) / (len(source_counts) * max(source_count, 1))
            for source_name, source_count in source_counts.items()
        }

        weights = np.asarray(labels.map(class_weights).astype(float), dtype=np.float64).copy()
        weights *= np.asarray(frame["source_name"].map(source_weights).astype(float), dtype=np.float64)
        weights /= max(weights.mean(), 1e-9)
        return weights.astype(np.float32)

    def _build_xgboost(self, labels: pd.Series) -> XGBClassifier:
        label_counts = labels.value_counts().to_dict()
        negative_count = label_counts.get(0, 0)
        positive_count = label_counts.get(1, 0)
        scale_pos_weight = float(negative_count / max(positive_count, 1))
        params = dict(self.xgb_config)
        params["scale_pos_weight"] = scale_pos_weight
        return XGBClassifier(**params)

    def _build_random_forest(self) -> RandomForestClassifier:
        return RandomForestClassifier(**self.rf_config)

    def _fit_model_with_fallback(self, model: Any, features: pd.DataFrame, labels: pd.Series, sample_weights: np.ndarray) -> None:
        try:
            model.fit(features, labels, sample_weight=sample_weights)
        except (PermissionError, OSError) as exc:
            if not hasattr(model, "n_jobs"):
                raise
            current_n_jobs = getattr(model, "n_jobs")
            if current_n_jobs in (None, 1):
                raise
            LOGGER.warning("Parallel fit failed for %s with n_jobs=%s: %s. Retrying with n_jobs=1.", type(model).__name__, current_n_jobs, exc)
            model.set_params(n_jobs=1)
            model.fit(features, labels, sample_weight=sample_weights)
