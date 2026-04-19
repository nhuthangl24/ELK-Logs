from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd

from src.utils.common import safe_divide

WEB_PORTS = {80, 443, 8080, 8443}
SQLI_KEYWORD_PATTERN = (
    r"(?i)\b("
    r"select|union(?:\s+all)?|insert|update|delete|drop|sleep|benchmark|waitfor|exec(?:ute)?|declare|cast|convert|"
    r"having|order\s+by|group\s+by|information_schema|load_file|outfile|xp_cmdshell|dbms_[a-z_]+|pg_sleep|"
    r"ascii\(|substring\(|concat\(|char\(|chr\(|hex\(|unhex\(|database\(|schema\(|table_name|column_name"
    r")"
)
SQLI_TAUTOLOGY_PATTERN = r"(?i)(?:\b(?:or|and|xor)\b\s+['\"`\(]*[a-z0-9_]+['\"`]*\s*=\s*['\"`]*[a-z0-9_]+['\"`]*)"
SQLI_COMMENT_PATTERN = r"(?i)(--|#|/\*|\*/|;)"
SQLI_ENCODED_META_PATTERN = r"(?i)(%27|%22|%23|%2d%2d|%3b|%2f\*|\*/|%3d|%28|%29)"
XSS_PATTERN = r"(?i)(<script|</script|javascript:|vbscript:|data:text/html|alert\(|document\.cookie|window\.location|<img|<svg|<iframe|<body)"
XSS_EVENT_HANDLER_PATTERN = r"(?i)(on[a-z]+\s*=)"


def _clean_string_series(series: pd.Series) -> pd.Series:
    return series.fillna("").astype(str).str.strip()


def _decode_string_series(series: pd.Series) -> pd.Series:
    return _clean_string_series(series).map(lambda value: unquote_plus(value))


def _build_log_count_feature(series: pd.Series, mapping: dict[str, int]) -> pd.Series:
    exact_counts = series.map(mapping).fillna(0).astype(np.float32)
    return np.log1p(exact_counts).astype(np.float32)


@dataclass
class FeatureBuilder:
    hash_bucket_size: int = 4096
    protocol_encoder: dict[str, int] = field(default_factory=dict)
    http_method_encoder: dict[str, int] = field(default_factory=dict)
    protocol_frequency: dict[str, float] = field(default_factory=dict)
    http_method_frequency: dict[str, float] = field(default_factory=dict)
    src_unique_dst_ports: dict[str, int] = field(default_factory=dict)
    count_maps: dict[str, dict[str, int]] = field(default_factory=dict)
    feature_list: list[str] = field(default_factory=list)

    def fit(self, frame: pd.DataFrame) -> "FeatureBuilder":
        protocol = self._normalize_protocol(frame["protocol"])
        http_method = self._normalize_http_method(frame["http_method"])
        uri = self._normalize_uri(frame["uri"])
        src_key = self._source_key(frame, protocol)
        dst_key = self._destination_key(frame, protocol)
        endpoint_key = self._endpoint_key(frame, uri)
        request_key = src_key + "|" + endpoint_key
        src_dst_key = src_key + "->" + dst_key

        self.protocol_encoder = {value: index + 1 for index, value in enumerate(sorted(protocol.unique())) if value}
        self.http_method_encoder = {value: index + 1 for index, value in enumerate(sorted(http_method.unique())) if value}
        self.protocol_frequency = (protocol.value_counts(dropna=False) / max(len(protocol), 1)).to_dict()
        self.http_method_frequency = (http_method.value_counts(dropna=False) / max(len(http_method), 1)).to_dict()
        self.src_unique_dst_ports = (
            pd.DataFrame({"src_key": src_key, "dst_port": pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0).astype(int)})
            .groupby("src_key")["dst_port"]
            .nunique()
            .to_dict()
        )
        self.count_maps = {
            "src": self._fit_count_map(src_key),
            "dst": self._fit_count_map(dst_key),
            "src_dst": self._fit_count_map(src_dst_key),
            "endpoint": self._fit_count_map(endpoint_key),
            "request": self._fit_count_map(request_key),
        }

        if not self.feature_list:
            self.feature_list = list(self.transform(frame.head(1)).columns)
        return self

    def fit_transform(self, frame: pd.DataFrame) -> pd.DataFrame:
        self.fit(frame)
        return self.transform(frame)

    def transform(self, frame: pd.DataFrame) -> pd.DataFrame:
        protocol = self._normalize_protocol(frame["protocol"])
        http_method = self._normalize_http_method(frame["http_method"])
        uri = self._normalize_uri(frame["uri"])
        uri_lower = uri.str.lower()
        src_ip = _clean_string_series(frame["src_ip"])
        dst_ip = _clean_string_series(frame["dst_ip"])
        src_key = self._source_key(frame, protocol)
        dst_key = self._destination_key(frame, protocol)
        endpoint_key = self._endpoint_key(frame, uri)
        request_key = src_key + "|" + endpoint_key
        src_dst_key = src_key + "->" + dst_key

        bytes_series = pd.to_numeric(frame["bytes"], errors="coerce").fillna(0).astype(np.float32)
        packets_series = pd.to_numeric(frame["packets"], errors="coerce").fillna(0).astype(np.float32)
        duration_series = pd.to_numeric(frame["duration"], errors="coerce").fillna(0).astype(np.float32)
        src_port = pd.to_numeric(frame["src_port"], errors="coerce").fillna(0).astype(np.int32)
        dst_port = pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0).astype(np.int32)

        query_params = np.where(uri.str.contains("=", regex=False), uri.str.count("&") + 1, 0).astype(np.float32)
        uri_length = uri.str.len().astype(np.float32)
        uri_path_depth = uri.str.count("/").astype(np.float32)
        uri_quote_count = uri.str.count(r"[\'\"`]").astype(np.float32)
        uri_angle_bracket_count = uri.str.count(r"[<>]").astype(np.float32)
        uri_equals_count = uri.str.count("=").astype(np.float32)
        uri_comment_hits = uri.str.count(SQLI_COMMENT_PATTERN).astype(np.float32)
        uri_encoded_meta_hits = uri_lower.str.count(SQLI_ENCODED_META_PATTERN).astype(np.float32)
        uri_sql_keyword_hits = uri.str.count(SQLI_KEYWORD_PATTERN).astype(np.float32)
        uri_sql_tautology_hits = uri.str.count(SQLI_TAUTOLOGY_PATTERN).astype(np.float32)
        uri_xss_keyword_hits = uri.str.count(XSS_PATTERN).astype(np.float32)
        uri_event_handler_hits = uri.str.count(XSS_EVENT_HANDLER_PATTERN).astype(np.float32)
        uri_script_tag_hits = uri_lower.str.count(r"(?i)(<script|</script|%3cscript|%3c/script)").astype(np.float32)
        uri_has_query_string = uri.str.contains(r"\?", regex=True, na=False).astype(np.float32)
        uri_has_percent_encoding = uri.str.contains(r"%[0-9a-fA-F]{2}", regex=True, na=False).astype(np.float32)
        special_char_ratio = safe_divide(uri.str.count(r"[^A-Za-z0-9/_\-.]").astype(np.float32), uri_length + 1.0).astype(np.float32)
        sql_attack_score = (
            uri_sql_keyword_hits * 2.0
            + uri_sql_tautology_hits * 3.0
            + uri_comment_hits
            + uri_encoded_meta_hits * 0.5
            + uri_quote_count * 0.25
        ).astype(np.float32)
        xss_attack_score = (
            uri_xss_keyword_hits * 2.0
            + uri_event_handler_hits * 2.0
            + uri_script_tag_hits * 2.0
            + uri_angle_bracket_count * 0.25
        ).astype(np.float32)

        is_http_like = (
            protocol.eq("HTTP")
            | http_method.ne("")
            | uri_length.gt(0)
            | dst_port.isin(WEB_PORTS)
        ).astype(np.float32)
        dst_port_is_web = dst_port.isin(WEB_PORTS).astype(np.float32)

        feature_frame = pd.DataFrame(
            {
                "src_port": src_port.astype(np.float32),
                "dst_port": dst_port.astype(np.float32),
                "bytes": bytes_series,
                "packets": packets_series,
                "duration": duration_series,
                "packets_per_flow": packets_series,
                "bytes_per_flow": bytes_series,
                "packet_byte_ratio": safe_divide(packets_series, bytes_series + 1.0).astype(np.float32),
                "bytes_per_second": safe_divide(bytes_series, duration_series + 1e-6).astype(np.float32),
                "packets_per_second": safe_divide(packets_series, duration_series + 1e-6).astype(np.float32),
                "duration_per_packet": safe_divide(duration_series, packets_series + 1.0).astype(np.float32),
                "protocol_encoded": protocol.map(self.protocol_encoder).fillna(0).astype(np.float32),
                "protocol_frequency": protocol.map(self.protocol_frequency).fillna(0).astype(np.float32),
                "http_method_encoded": http_method.map(self.http_method_encoder).fillna(0).astype(np.float32),
                "http_method_frequency": http_method.map(self.http_method_frequency).fillna(0).astype(np.float32),
                "uri_length": uri_length,
                "uri_path_depth": uri_path_depth,
                "uri_query_param_count": query_params,
                "uri_equals_count": uri_equals_count,
                "uri_quote_count": uri_quote_count,
                "uri_angle_bracket_count": uri_angle_bracket_count,
                "uri_has_query_string": uri_has_query_string,
                "uri_has_percent_encoding": uri_has_percent_encoding,
                "uri_sql_keyword_hits": uri_sql_keyword_hits,
                "uri_sql_tautology_hits": uri_sql_tautology_hits,
                "uri_sql_comment_hits": uri_comment_hits,
                "uri_sql_encoded_meta_hits": uri_encoded_meta_hits,
                "uri_xss_keyword_hits": uri_xss_keyword_hits,
                "uri_xss_event_handler_hits": uri_event_handler_hits,
                "uri_xss_script_tag_hits": uri_script_tag_hits,
                "uri_special_char_ratio": special_char_ratio,
                "sql_attack_score": sql_attack_score,
                "xss_attack_score": xss_attack_score,
                "http_like_request": is_http_like,
                "protocol_is_http": protocol.eq("HTTP").astype(np.float32),
                "unique_dst_ports_per_source": np.log1p(src_key.map(self.src_unique_dst_ports).fillna(0).astype(np.float32)),
                "repeated_access_count": _build_log_count_feature(request_key, self.count_maps.get("request", {})),
                "src_ip_frequency": _build_log_count_feature(src_key, self.count_maps.get("src", {})),
                "dst_ip_frequency": _build_log_count_feature(dst_key, self.count_maps.get("dst", {})),
                "src_dst_pair_frequency": _build_log_count_feature(src_dst_key, self.count_maps.get("src_dst", {})),
                "endpoint_frequency": _build_log_count_feature(endpoint_key, self.count_maps.get("endpoint", {})),
                "src_ip_is_private": self._is_private_ip(src_ip).astype(np.float32),
                "dst_ip_is_private": self._is_private_ip(dst_ip).astype(np.float32),
                "src_port_is_system": src_port.lt(1024).astype(np.float32),
                "dst_port_is_system": dst_port.lt(1024).astype(np.float32),
                "dst_port_is_web": dst_port_is_web,
                "payload_present": uri_length.gt(0).astype(np.float32),
            }
        )
        return feature_frame.astype(np.float32)

    def to_encoder_payload(self) -> dict[str, Any]:
        return {
            "hash_bucket_size": self.hash_bucket_size,
            "protocol_encoder": self.protocol_encoder,
            "http_method_encoder": self.http_method_encoder,
            "protocol_frequency": self.protocol_frequency,
            "http_method_frequency": self.http_method_frequency,
            "count_map_sizes": {name: len(mapping) for name, mapping in self.count_maps.items()},
            "feature_list": self.feature_list,
        }

    def _normalize_protocol(self, series: pd.Series) -> pd.Series:
        protocol = _clean_string_series(series).str.upper()
        return protocol.replace({"-": "", "0": ""})

    def _normalize_http_method(self, series: pd.Series) -> pd.Series:
        return _clean_string_series(series).str.upper()

    def _normalize_uri(self, series: pd.Series) -> pd.Series:
        return _decode_string_series(series)

    def _source_key(self, frame: pd.DataFrame, protocol: pd.Series) -> pd.Series:
        src_ip = _clean_string_series(frame["src_ip"])
        return src_ip.where(src_ip.ne(""), "NO_SRC::" + protocol.where(protocol.ne(""), "UNKNOWN"))

    def _destination_key(self, frame: pd.DataFrame, protocol: pd.Series) -> pd.Series:
        dst_ip = _clean_string_series(frame["dst_ip"])
        dst_port = pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0).astype(int).astype(str)
        fallback = "NO_DST::" + protocol.where(protocol.ne(""), "UNKNOWN") + "::" + dst_port
        return dst_ip.where(dst_ip.ne(""), fallback)

    def _endpoint_key(self, frame: pd.DataFrame, uri: pd.Series) -> pd.Series:
        dst_ip = _clean_string_series(frame["dst_ip"])
        dst_port = pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0).astype(int).astype(str)
        fallback = dst_ip.where(dst_ip.ne(""), "NO_ENDPOINT") + "::" + dst_port
        return uri.where(uri.ne(""), fallback)

    def _fit_count_map(self, series: pd.Series, min_count: int = 2) -> dict[str, int]:
        counts = series.value_counts(dropna=False)
        filtered = counts[counts >= min_count]
        return {str(key): int(value) for key, value in filtered.to_dict().items()}

    def _is_private_ip(self, series: pd.Series) -> pd.Series:
        return series.str.match(
            r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)",
            na=False,
        )
