from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

from src.models.artifacts import load_runtime_artifacts
from src.preprocess.schema import normalize_for_inference
from src.features.feature_builder import (
    SQLI_COMMENT_PATTERN,
    SQLI_ENCODED_META_PATTERN,
    SQLI_KEYWORD_PATTERN,
    SQLI_TAUTOLOGY_PATTERN,
    XSS_EVENT_HANDLER_PATTERN,
    XSS_PATTERN,
)
from src.utils.serialization import save_json


class CybersecurityPredictor:
    def __init__(self, artifact_dir: Path) -> None:
        artifacts = load_runtime_artifacts(artifact_dir)
        self.model = artifacts["model"]
        self.feature_builder = artifacts["feature_builder"]
        self.feature_list = artifacts["feature_list"]
        self.artifact_dir = artifact_dir

    def predict_file(self, input_path: Path, output_path: Path | None = None) -> list[dict[str, Any]]:
        payload = self._load_payload(input_path)
        results = self.predict_payload(payload)

        if output_path is not None:
            save_json(results, output_path)
        return results

    def predict_payload(self, payload: Any) -> list[dict[str, Any]]:
        raw_frame = self._payload_to_frame(payload)
        return self.predict_frame(raw_frame)

    def predict_frame(self, raw_frame: pd.DataFrame) -> list[dict[str, Any]]:
        primary_frame = normalize_for_inference(raw_frame)
        primary_probabilities = self._predict_probabilities(primary_frame)

        web_view_probabilities = [None] * len(raw_frame)
        web_view_indices: list[int] = []
        web_view_uris: list[str] = []

        for index, record in enumerate(raw_frame.to_dict(orient="records")):
            uri = str(record.get("uri", "") or "").strip()
            if len(record) > 1 and uri and self._looks_suspicious_web_payload(uri):
                web_view_indices.append(index)
                web_view_uris.append(uri)

        if web_view_uris:
            web_view_frame = normalize_for_inference(pd.DataFrame({"payload": web_view_uris}))
            web_probabilities = self._predict_probabilities(web_view_frame)
            for index, probability in zip(web_view_indices, web_probabilities):
                web_view_probabilities[index] = probability

        results = []
        for index, record in enumerate(primary_frame.to_dict(orient="records")):
            primary_probability = float(primary_probabilities[index])
            payload_probability = web_view_probabilities[index]
            final_probability = primary_probability
            selected_view = "primary"
            if payload_probability is not None and float(payload_probability) > final_probability:
                final_probability = float(payload_probability)
                selected_view = "web_payload"

            results.append(
                {
                    "index": index,
                    "prediction": int(final_probability >= 0.5),
                    "malicious_probability": final_probability,
                    "selected_view": selected_view,
                    "normalized_record": {
                        key: record[key]
                        for key in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "packets", "duration", "http_method", "uri"]
                    },
                }
            )

        return results

    def _predict_probabilities(self, normalized_frame: pd.DataFrame) -> list[float]:
        features = self.feature_builder.transform(normalized_frame)[self.feature_list]
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(features)[:, 1]
        else:
            probabilities = self.model.predict(features)
        return [float(value) for value in probabilities]

    def _load_payload(self, input_path: Path) -> Any:
        with input_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _payload_to_frame(self, payload: Any) -> pd.DataFrame:
        if isinstance(payload, dict):
            if "records" in payload and isinstance(payload["records"], list):
                return pd.DataFrame(payload["records"])
            return pd.DataFrame([payload])
        if isinstance(payload, list):
            if payload and isinstance(payload[0], dict):
                return pd.DataFrame(payload)
            return pd.DataFrame({"payload": payload})
        raise ValueError("Prediction input must be a JSON object, a list of objects, or a list of payload strings.")

    def _looks_suspicious_web_payload(self, uri: str) -> bool:
        candidate = uri.strip()
        suspicious_patterns = [
            SQLI_KEYWORD_PATTERN,
            SQLI_TAUTOLOGY_PATTERN,
            SQLI_COMMENT_PATTERN,
            SQLI_ENCODED_META_PATTERN,
            XSS_PATTERN,
            XSS_EVENT_HANDLER_PATTERN,
        ]
        return any(re.search(pattern, candidate) is not None for pattern in suspicious_patterns)
