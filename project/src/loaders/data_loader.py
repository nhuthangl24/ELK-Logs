from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Generator

import pandas as pd

from src.preprocess.schema import (
    modsec_merged_files,
    normalize_cic_dataframe,
    normalize_firewall_dataframe,
    normalize_modsec_payloads,
    normalize_unsw_dataframe,
)

LOGGER = logging.getLogger(__name__)


class UnifiedDatasetLoader:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.search_roots = [Path(path) for path in config["data_search_roots"]]
        self.csv_chunksize = int(config["loader"]["csv_chunksize"])
        self.modsec_batch_size = int(config["loader"]["modsec_batch_size"])
        self.cic_encodings = list(config["loader"]["cic_encodings"])

    def load_all(self) -> pd.DataFrame:
        dataset_paths = self.discover_dataset_paths()
        frames = [
            self.load_unsw(dataset_paths["unsw_train"], dataset_paths["unsw_test"]),
            self.load_cic(dataset_paths["cic_dir"]),
            self.load_modsec(dataset_paths["modsec_dir"]),
            self.load_firewall(dataset_paths["firewall_dir"]),
        ]

        merged = pd.concat(frames, ignore_index=True, copy=False)
        LOGGER.info("Merged dataset rows=%s malicious=%s benign=%s", len(merged), int(merged["label"].sum()), int((merged["label"] == 0).sum()))
        LOGGER.info("Rows by source: %s", merged["source_name"].value_counts().to_dict())
        return merged

    def discover_dataset_paths(self) -> dict[str, Path]:
        resolved: dict[str, Path] = {}
        resolved["unsw_train"] = self._find_file("UNSW_NB15_training-set.parquet")
        resolved["unsw_test"] = self._find_file("UNSW_NB15_testing-set.parquet")
        resolved["cic_dir"] = self._find_directory_prefix("CIC-IDS")
        resolved["modsec_dir"] = self._find_directory_exact("modsec-learn-dataset")
        resolved["firewall_dir"] = self._find_directory_exact("Firewall")
        return resolved

    def load_unsw(self, train_path: Path, test_path: Path) -> pd.DataFrame:
        LOGGER.info("Loading UNSW parquet files")
        frames = []
        for path in [train_path, test_path]:
            LOGGER.info("Reading %s", path)
            raw_frame = pd.read_parquet(path)
            frames.append(normalize_unsw_dataframe(raw_frame, source_name="UNSW_NB15"))
        return pd.concat(frames, ignore_index=True, copy=False)

    def load_cic(self, cic_dir: Path) -> pd.DataFrame:
        LOGGER.info("Loading CIC-IDS-2017 CSV files from %s", cic_dir)
        normalized_chunks: list[pd.DataFrame] = []
        for csv_path in sorted(cic_dir.glob("*.csv")):
            LOGGER.info("Reading %s", csv_path.name)
            for chunk in self._read_csv_chunks(csv_path):
                normalized_chunks.append(normalize_cic_dataframe(chunk, source_name="CIC_IDS_2017"))
        if not normalized_chunks:
            raise FileNotFoundError(f"No CIC CSV files found in {cic_dir}")
        return pd.concat(normalized_chunks, ignore_index=True, copy=False)

    def load_modsec(self, modsec_dir: Path) -> pd.DataFrame:
        LOGGER.info("Loading ModSecurity JSON data from %s", modsec_dir)
        frames: list[pd.DataFrame] = []
        for json_path in modsec_merged_files(modsec_dir):
            label_value = 0 if "legitimate" in str(json_path).lower() else 1
            LOGGER.info("Reading %s", json_path)
            payload_buffer: list[str] = []
            label_buffer: list[int] = []
            for payload in self._stream_json_array(json_path):
                payload_buffer.append(str(payload))
                label_buffer.append(label_value)
                if len(payload_buffer) >= self.modsec_batch_size:
                    frames.append(normalize_modsec_payloads(payload_buffer, label_buffer, source_name="MODSEC_LEARN"))
                    payload_buffer = []
                    label_buffer = []
            if payload_buffer:
                frames.append(normalize_modsec_payloads(payload_buffer, label_buffer, source_name="MODSEC_LEARN"))
        if not frames:
            raise FileNotFoundError(f"No ModSecurity JSON files found in {modsec_dir}")
        return pd.concat(frames, ignore_index=True, copy=False)

    def load_firewall(self, firewall_dir: Path) -> pd.DataFrame:
        LOGGER.info("Loading firewall CSV files from %s", firewall_dir)
        frames: list[pd.DataFrame] = []
        for csv_path in sorted(firewall_dir.glob("*.csv")):
            for chunk in self._read_csv_chunks(csv_path):
                frames.append(normalize_firewall_dataframe(chunk, source_name="FIREWALL"))
        if not frames:
            raise FileNotFoundError(f"No firewall CSV files found in {firewall_dir}")
        return pd.concat(frames, ignore_index=True, copy=False)

    def _find_file(self, file_name: str) -> Path:
        for search_root in self.search_roots:
            candidate = search_root / file_name
            if candidate.exists():
                return candidate
            matches = list(search_root.rglob(file_name))
            if matches:
                return matches[0]
        raise FileNotFoundError(f"Unable to locate required dataset file: {file_name}")

    def _find_directory_exact(self, directory_name: str) -> Path:
        for search_root in self.search_roots:
            candidate = search_root / directory_name
            if candidate.exists():
                return candidate
            for path in search_root.rglob("*"):
                if path.is_dir() and path.name.lower() == directory_name.lower():
                    return path
        raise FileNotFoundError(f"Unable to locate required directory: {directory_name}")

    def _find_directory_prefix(self, prefix: str) -> Path:
        for search_root in self.search_roots:
            for path in sorted(search_root.iterdir()):
                if path.is_dir() and path.name.lower().replace(" ", "").startswith(prefix.lower().replace(" ", "")):
                    return path
            matches = [
                path
                for path in search_root.rglob("*")
                if path.is_dir() and path.name.lower().replace(" ", "").startswith(prefix.lower().replace(" ", ""))
            ]
            if matches:
                return sorted(matches)[0]
        raise FileNotFoundError(f"Unable to locate required directory with prefix: {prefix}")

    def _read_csv_chunks(self, csv_path: Path) -> Generator[pd.DataFrame, None, None]:
        last_exception: Exception | None = None
        for encoding in self.cic_encodings:
            try:
                csv_reader = pd.read_csv(
                    csv_path,
                    chunksize=self.csv_chunksize,
                    encoding=encoding,
                    encoding_errors="replace",
                    low_memory=False,
                )
                for chunk in csv_reader:
                    yield chunk
                return
            except Exception as exc:  # pragma: no cover - defensive retry logic
                last_exception = exc
                LOGGER.warning("Failed to read %s with encoding=%s: %s", csv_path, encoding, exc)
        if last_exception is not None:
            raise last_exception

    def _stream_json_array(self, json_path: Path) -> Generator[str, None, None]:
        decoder = json.JSONDecoder()
        buffer = ""
        in_array = False
        with json_path.open("r", encoding="utf-8") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                buffer += chunk
                while True:
                    buffer = buffer.lstrip()
                    if not buffer:
                        break
                    if not in_array:
                        if buffer[0] != "[":
                            raise ValueError(f"Expected JSON array in {json_path}")
                        in_array = True
                        buffer = buffer[1:]
                        continue
                    if buffer[0] == "]":
                        return
                    if buffer[0] == ",":
                        buffer = buffer[1:]
                        continue
                    try:
                        value, offset = decoder.raw_decode(buffer)
                    except json.JSONDecodeError:
                        break
                    yield str(value)
                    buffer = buffer[offset:]
        buffer = buffer.strip()
        if buffer not in {"", "]"}:
            raise ValueError(f"Incomplete JSON stream while reading {json_path}")
