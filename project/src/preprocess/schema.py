from __future__ import annotations

from pathlib import Path
from typing import Iterable
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd

UNIFIED_SCHEMA_COLUMNS = [
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
]

STRING_COLUMNS = ["src_ip", "dst_ip", "protocol", "http_method", "uri"]
NUMERIC_COLUMNS = ["src_port", "dst_port", "bytes", "packets", "duration", "label"]

UNIFIED_ALIAS_MAP: dict[str, list[str]] = {
    "src_ip": ["srcip", "sourceip", "source_ip", "src_ip"],
    "dst_ip": ["dstip", "destinationip", "destination_ip", "dst_ip"],
    "src_port": ["srcport", "sourceport", "source_port", "sport", "src_port"],
    "dst_port": ["dstport", "destinationport", "destination_port", "dsport", "destinationport", "dst_port"],
    "protocol": ["protocol", "proto", "protocoltype"],
    "bytes": ["bytes", "bytecount", "totalbytes", "flowbytes"],
    "packets": ["packets", "packetcount", "totalpackets", "flowpackets"],
    "duration": ["duration", "dur", "flowduration"],
    "http_method": ["httpmethod", "method", "http_method"],
    "uri": ["uri", "path", "request", "payload", "query", "url", "requesturi"],
    "label": ["label", "attackcat", "attack_cat", "class"],
}


def normalize_column_name(column_name: str) -> str:
    return "".join(character.lower() for character in str(column_name).strip() if character.isalnum() or character == "_")


def _column_lookup(frame: pd.DataFrame) -> dict[str, str]:
    return {normalize_column_name(column_name): column_name for column_name in frame.columns}


def _find_column(frame: pd.DataFrame, aliases: Iterable[str]) -> str | None:
    lookup = _column_lookup(frame)
    for alias in aliases:
        match = lookup.get(normalize_column_name(alias))
        if match is not None:
            return match
    return None


def _series_or_default(frame: pd.DataFrame, aliases: Iterable[str], default: str | int | float) -> pd.Series:
    column = _find_column(frame, aliases)
    if column is None:
        return pd.Series([default] * len(frame), index=frame.index)
    return frame[column]


def _coerce_string(series: pd.Series) -> pd.Series:
    return series.fillna("").astype(str).str.strip()


def _coerce_numeric(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce").fillna(0)
    return numeric


def _clean_protocol(series: pd.Series) -> pd.Series:
    protocol = _coerce_string(series).str.upper()
    return protocol.replace({"-": "", "0": ""})


def _coerce_port(series: pd.Series) -> pd.Series:
    port = _coerce_numeric(series).clip(lower=0, upper=65535)
    return port.round().astype(np.int32)


def _map_text_label_to_binary(series: pd.Series, default_value: int = 0) -> pd.Series:
    cleaned = _coerce_string(series).str.lower()
    result = pd.Series(np.full(len(series), default_value, dtype=np.int8), index=series.index)

    numeric = pd.to_numeric(series, errors="coerce")
    numeric_mask = numeric.notna()
    if numeric_mask.any():
        result.loc[numeric_mask] = (numeric.loc[numeric_mask] > 0).astype(np.int8)

    benign_keywords = [
        "benign",
        "normal",
        "legitimate",
        "allow",
        "allowed",
        "clean",
        "successful",
    ]
    malicious_keywords = [
        "attack",
        "malicious",
        "sqli",
        "sql injection",
        "sqli",
        "xss",
        "brute",
        "dos",
        "ddos",
        "portscan",
        "scan",
        "bot",
        "infiltration",
        "exploit",
        "fuzzer",
        "reconnaissance",
        "backdoor",
        "shellcode",
        "worm",
        "generic",
        "deny",
        "denied",
        "blocked",
        "anomaly",
        "abnormal",
    ]

    benign_mask = pd.Series(False, index=series.index)
    for keyword in benign_keywords:
        benign_mask = benign_mask | cleaned.str.contains(keyword, regex=False, na=False)

    malicious_mask = pd.Series(False, index=series.index)
    for keyword in malicious_keywords:
        malicious_mask = malicious_mask | cleaned.str.contains(keyword, regex=False, na=False)

    result.loc[benign_mask] = 0
    result.loc[malicious_mask] = 1
    return result.astype(np.int8)


def finalize_unified_schema(frame: pd.DataFrame, source_name: str, original_label: pd.Series | None = None, allow_missing_label: bool = False) -> pd.DataFrame:
    normalized = frame.copy()

    for column_name in STRING_COLUMNS:
        if column_name not in normalized:
            normalized[column_name] = ""
        normalized[column_name] = _coerce_string(normalized[column_name])

    for column_name in NUMERIC_COLUMNS:
        if column_name not in normalized:
            default_value = 0 if column_name != "label" or allow_missing_label else 0
            normalized[column_name] = default_value
        normalized[column_name] = _coerce_numeric(normalized[column_name])

    normalized["src_port"] = _coerce_port(normalized["src_port"])
    normalized["dst_port"] = _coerce_port(normalized["dst_port"])
    normalized["bytes"] = normalized["bytes"].astype(np.float32)
    normalized["packets"] = normalized["packets"].astype(np.float32)
    normalized["duration"] = normalized["duration"].astype(np.float32)

    if allow_missing_label:
        normalized["label"] = normalized["label"].fillna(0).astype(np.int8)
    else:
        normalized["label"] = _map_text_label_to_binary(normalized["label"]).astype(np.int8)

    normalized["protocol"] = _clean_protocol(normalized["protocol"])
    normalized["http_method"] = _coerce_string(normalized["http_method"]).str.upper()
    normalized["source_name"] = source_name
    normalized["original_label_text"] = _coerce_string(original_label if original_label is not None else normalized["label"])

    ordered_columns = UNIFIED_SCHEMA_COLUMNS + ["source_name", "original_label_text"]
    return normalized[ordered_columns].reset_index(drop=True)


def normalize_unsw_dataframe(frame: pd.DataFrame, source_name: str = "UNSW_NB15") -> pd.DataFrame:
    normalized = pd.DataFrame(index=frame.index)
    normalized["src_ip"] = ""
    normalized["dst_ip"] = ""
    normalized["src_port"] = 0
    normalized["dst_port"] = 0
    normalized["protocol"] = _series_or_default(frame, ["proto", "protocol"], "")
    normalized["bytes"] = _coerce_numeric(_series_or_default(frame, ["sbytes"], 0)) + _coerce_numeric(
        _series_or_default(frame, ["dbytes"], 0)
    )
    normalized["packets"] = _coerce_numeric(_series_or_default(frame, ["spkts"], 0)) + _coerce_numeric(
        _series_or_default(frame, ["dpkts"], 0)
    )
    normalized["duration"] = _coerce_numeric(_series_or_default(frame, ["dur", "duration"], 0))
    http_hint = _coerce_numeric(_series_or_default(frame, ["ct_flw_http_mthd"], 0))
    normalized["http_method"] = np.where(http_hint > 0, "UNKNOWN_HTTP", "")
    normalized["uri"] = ""
    label_series = _series_or_default(frame, ["label", "attack_cat"], 0)
    normalized["label"] = label_series
    original_label = _series_or_default(frame, ["attack_cat", "label"], "")
    return finalize_unified_schema(normalized, source_name=source_name, original_label=original_label)


def normalize_cic_dataframe(frame: pd.DataFrame, source_name: str = "CIC_IDS_2017") -> pd.DataFrame:
    normalized = pd.DataFrame(index=frame.index)
    normalized["src_ip"] = _series_or_default(frame, ["Source IP", "Src IP", "src_ip"], "")
    normalized["dst_ip"] = _series_or_default(frame, ["Destination IP", "Dst IP", "dst_ip"], "")
    normalized["src_port"] = _series_or_default(frame, ["Source Port", "Src Port", "src_port"], 0)
    normalized["dst_port"] = _series_or_default(frame, ["Destination Port", "Dst Port", "dst_port"], 0)
    normalized["protocol"] = _series_or_default(frame, ["Protocol", "protocol", "Proto"], "")
    total_fwd = _coerce_numeric(_series_or_default(frame, ["Total Length of Fwd Packets", "Subflow Fwd Bytes"], 0))
    total_bwd = _coerce_numeric(_series_or_default(frame, ["Total Length of Bwd Packets", "Subflow Bwd Bytes"], 0))
    normalized["bytes"] = total_fwd + total_bwd
    total_fwd_packets = _coerce_numeric(_series_or_default(frame, ["Total Fwd Packets", "Subflow Fwd Packets"], 0))
    total_bwd_packets = _coerce_numeric(_series_or_default(frame, ["Total Backward Packets", "Subflow Bwd Packets"], 0))
    normalized["packets"] = total_fwd_packets + total_bwd_packets
    flow_duration = _coerce_numeric(_series_or_default(frame, ["Flow Duration"], 0))
    normalized["duration"] = flow_duration / np.float32(1_000_000.0)
    normalized["http_method"] = ""
    normalized["uri"] = ""
    label_series = _series_or_default(frame, ["Label", " Label", "label"], "")
    normalized["label"] = label_series
    return finalize_unified_schema(normalized, source_name=source_name, original_label=label_series)


def normalize_firewall_dataframe(frame: pd.DataFrame, source_name: str = "FIREWALL") -> pd.DataFrame:
    normalized = pd.DataFrame(index=frame.index)
    normalized["src_ip"] = _series_or_default(frame, ["Src IP", "src_ip"], "")
    normalized["dst_ip"] = _series_or_default(frame, ["Dst IP", "dst_ip"], "")
    normalized["src_port"] = _series_or_default(frame, ["Src port", "src_port"], 0)
    normalized["dst_port"] = _series_or_default(frame, ["Dst port", "dst_port"], 0)
    normalized["protocol"] = _series_or_default(frame, ["protocol", "proto"], "")
    normalized["bytes"] = 0
    normalized["packets"] = _coerce_numeric(_series_or_default(frame, ["Log occurrence"], 1))
    normalized["duration"] = 0
    normalized["http_method"] = ""
    normalized["uri"] = ""

    log_subtype = _coerce_string(_series_or_default(frame, ["Log subtype"], ""))
    firewall_rule_name = _coerce_string(_series_or_default(frame, ["Firewall rule name"], ""))
    message = _coerce_string(_series_or_default(frame, ["Message"], ""))
    rule_type = _coerce_numeric(_series_or_default(frame, ["Rule type"], 0))

    malicious_mask = (
        log_subtype.str.lower().ne("allowed")
        | firewall_rule_name.str.contains(r"block|deny|drop", case=False, regex=True, na=False)
        | message.str.len().gt(0)
        | rule_type.eq(0)
    )
    normalized["label"] = malicious_mask.astype(np.int8)
    original_label = log_subtype.where(log_subtype.str.len().gt(0), firewall_rule_name.where(firewall_rule_name.str.len().gt(0), message))
    return finalize_unified_schema(normalized, source_name=source_name, original_label=original_label)


def _normalize_modsec_payload(payload: str) -> str:
    return unquote_plus(str(payload)).strip()


def normalize_modsec_payloads(payloads: list[str], labels: list[int], source_name: str = "MODSEC_LEARN") -> pd.DataFrame:
    frame = pd.DataFrame({"payload": payloads, "label": labels})
    normalized = pd.DataFrame(index=frame.index)
    normalized["src_ip"] = ""
    normalized["dst_ip"] = ""
    normalized["src_port"] = 0
    normalized["dst_port"] = 0
    normalized["protocol"] = "HTTP"
    decoded_payload = frame["payload"].map(_normalize_modsec_payload)
    normalized["bytes"] = decoded_payload.str.len().astype(np.float32)
    normalized["packets"] = 1
    normalized["duration"] = 0
    normalized["http_method"] = "GET"
    normalized["uri"] = decoded_payload
    normalized["label"] = frame["label"]
    return finalize_unified_schema(normalized, source_name=source_name, original_label=frame["label"].astype(str))


def normalize_generic_dataframe(frame: pd.DataFrame, source_name: str = "INFERENCE", allow_missing_label: bool = True) -> pd.DataFrame:
    normalized = pd.DataFrame(index=frame.index)
    for target_column, aliases in UNIFIED_ALIAS_MAP.items():
        normalized[target_column] = _series_or_default(frame, aliases, 0 if target_column in NUMERIC_COLUMNS else "")
    return finalize_unified_schema(
        normalized,
        source_name=source_name,
        original_label=_series_or_default(frame, ["label"], ""),
        allow_missing_label=allow_missing_label,
    )


def detect_dataframe_format(frame: pd.DataFrame) -> str:
    normalized_columns = {normalize_column_name(column_name) for column_name in frame.columns}
    if {"spkts", "dpkts", "sbytes", "dbytes"}.issubset(normalized_columns):
        return "unsw"
    if "destinationport" in normalized_columns and ("totalfwdpackets" in normalized_columns or "subflowfwdpackets" in normalized_columns):
        return "cic"
    if {"srcip", "dstip"}.issubset(normalized_columns) and ("firewallrulename" in normalized_columns or "logsubtype" in normalized_columns):
        return "firewall"
    if len(frame.columns) == 1:
        return "modsec"
    return "generic"


def normalize_for_inference(frame: pd.DataFrame) -> pd.DataFrame:
    detected_format = detect_dataframe_format(frame)
    if detected_format == "unsw":
        return normalize_unsw_dataframe(frame, source_name="INFERENCE_UNSW")
    if detected_format == "cic":
        return normalize_cic_dataframe(frame, source_name="INFERENCE_CIC")
    if detected_format == "firewall":
        return normalize_firewall_dataframe(frame, source_name="INFERENCE_FIREWALL")
    if detected_format == "modsec":
        first_column = frame.columns[0]
        payloads = frame[first_column].fillna("").astype(str).tolist()
        return normalize_modsec_payloads(payloads=payloads, labels=[0] * len(payloads), source_name="INFERENCE_MODSEC").drop(
            columns=["label"]
        ).assign(label=0)
    return normalize_generic_dataframe(frame, source_name="INFERENCE_GENERIC", allow_missing_label=True)


def modsec_merged_files(modsec_root: Path) -> list[Path]:
    preferred_files = [
        modsec_root / "legitimate" / "legitimate_dataset.json",
        modsec_root / "malicious" / "sqli_dataset.json",
    ]
    existing_preferred = [path for path in preferred_files if path.exists()]
    if existing_preferred:
        return existing_preferred
    return sorted(path for path in modsec_root.rglob("*.json") if path.is_file())
