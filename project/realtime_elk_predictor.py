from __future__ import annotations

import json
import os
import time
from html import escape
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from src.inference.predictor import CybersecurityPredictor

ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", "artifacts"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "realtime_output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

ES_URL = os.getenv("ES_URL", "https://127.0.0.1:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "changeme")
ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"

OUTPUT_INDEX = os.getenv("OUTPUT_INDEX", "ml-cyber-alerts")
OUTPUT_TO_ES = os.getenv("OUTPUT_TO_ES", "false").lower() == "true"
INDEX_ONLY_ALERTS = os.getenv("INDEX_ONLY_ALERTS", "false").lower() == "true"
SAVE_LOCAL_OUTPUT = os.getenv("SAVE_LOCAL_OUTPUT", "false").lower() == "true"
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "2"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "200"))
START_FROM_LATEST = os.getenv("START_FROM_LATEST", "true").lower() == "true"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "true").lower() == "true" and bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
TELEGRAM_MIN_PROBABILITY = float(os.getenv("TELEGRAM_MIN_PROBABILITY", "0.80"))
TELEGRAM_TIMEOUT_SECONDS = float(os.getenv("TELEGRAM_TIMEOUT_SECONDS", "10"))
TELEGRAM_SEND_ONLY_ALERTS = os.getenv("TELEGRAM_SEND_ONLY_ALERTS", "true").lower() == "true"
TELEGRAM_MESSAGE_PREFIX = os.getenv("TELEGRAM_MESSAGE_PREFIX", "Cyber Alert").strip()

SOURCES: dict[str, dict[str, Any]] = {
    "pfelkfw": {
        "index": os.getenv("PFELK_INDEX", "*-pfelk-firewall*"),
        "query": {
            "size": BATCH_SIZE,
            "_source": True,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
            "query": {"match_all": {}},
        },
    },
    "ids_to_elk": {
        "index": os.getenv("IDS_INDEX", "filebeat-*"),
        "query": {
            "size": BATCH_SIZE,
            "_source": True,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.module": "suricata"}},
                        {"term": {"event.kind": "alert"}},
                    ]
                }
            },
        },
    },
}


def flatten_dict(data: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    items: dict[str, Any] = {}
    for key, value in data.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(flatten_dict(value, new_key, sep=sep))
        else:
            items[new_key] = value
    return items


def safe(value: Any, default: Any = "") -> Any:
    if value is None:
        return default
    if isinstance(value, list):
        return value[0] if value else default
    return value


def coalesce(flat: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = safe(flat.get(key), None)
        if value in (None, ""):
            continue
        return value
    return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(safe(value, default)))
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(safe(value, default))
    except (TypeError, ValueError):
        return default


def event_duration_seconds(flat: dict[str, Any]) -> float:
    duration_value = coalesce(
        flat,
        "event.duration",
        "suricata.eve.flow.age",
        "suricata.eve.flow.start",
        default=0.0,
    )
    duration = as_float(duration_value, 0.0)
    if duration > 1_000_000:
        return duration / 1_000_000_000.0
    return duration


def network_bytes(flat: dict[str, Any]) -> float:
    explicit_total = coalesce(flat, "network.bytes", "flow.bytes_toserver", "flow.bytes_toclient", default=None)
    if explicit_total is not None:
        if "network.bytes" in flat:
            return as_float(flat.get("network.bytes"), 0.0)
    source_bytes = as_float(coalesce(flat, "source.bytes", "suricata.eve.flow.bytes_toserver", default=0.0), 0.0)
    destination_bytes = as_float(coalesce(flat, "destination.bytes", "suricata.eve.flow.bytes_toclient", default=0.0), 0.0)
    combined = source_bytes + destination_bytes
    if combined > 0:
        return combined
    return as_float(coalesce(flat, "network.bytes", default=0.0), 0.0)


def network_packets(flat: dict[str, Any]) -> float:
    total_packets = as_float(coalesce(flat, "network.packets", default=0.0), 0.0)
    if total_packets > 0:
        return total_packets
    source_packets = as_float(coalesce(flat, "source.packets", "suricata.eve.flow.pkts_toserver", default=0.0), 0.0)
    destination_packets = as_float(coalesce(flat, "destination.packets", "suricata.eve.flow.pkts_toclient", default=0.0), 0.0)
    combined = source_packets + destination_packets
    return combined if combined > 0 else 1.0


def build_uri(flat: dict[str, Any]) -> str:
    original = str(coalesce(flat, "url.original", "http.request.referrer", "http.request.body.content", default="")).strip()
    if original:
        return original

    path = str(
        coalesce(
            flat,
            "url.path",
            "http.request.path",
            "suricata.eve.http.url",
            "suricata.eve.http.hostname",
            default="",
        )
    ).strip()
    query = str(coalesce(flat, "url.query", "http.request.query", default="")).strip()
    if path and query:
        return f"{path}?{query}"
    if path:
        return path

    request_line = str(coalesce(flat, "http.request.line", "suricata.eve.http.http_user_agent", default="")).strip()
    if request_line:
        return request_line
    return ""


def http_method(flat: dict[str, Any]) -> str:
    return str(
        coalesce(
            flat,
            "http.request.method",
            "http.method",
            "suricata.eve.http.http_method",
            "request.method",
            default="",
        )
    ).upper()


def protocol(flat: dict[str, Any]) -> str:
    return str(coalesce(flat, "network.protocol", "network.transport", "protocol", default="")).upper()


def map_pfelkfw(hit: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = hit.get("_source", {})
    flat = flatten_dict(source)
    unified = {
        "src_ip": str(coalesce(flat, "source.ip", "src_ip", default="")),
        "dst_ip": str(coalesce(flat, "destination.ip", "dst_ip", default="")),
        "src_port": as_int(coalesce(flat, "source.port", "src_port", default=0)),
        "dst_port": as_int(coalesce(flat, "destination.port", "dst_port", default=0)),
        "protocol": protocol(flat),
        "bytes": network_bytes(flat),
        "packets": network_packets(flat),
        "duration": event_duration_seconds(flat),
        "http_method": http_method(flat),
        "uri": build_uri(flat),
        "label": 0,
    }
    metadata = {
        "@timestamp": source.get("@timestamp", ""),
        "source_type": "pfelkfw",
        "event_action": str(coalesce(flat, "event.action", default="")),
        "event_reason": str(coalesce(flat, "event.reason", "message", default="")),
        "rule_name": str(coalesce(flat, "rule.name", "firewall.rule.name", default="")),
        "source_index": hit.get("_index", ""),
        "source_id": hit.get("_id", ""),
    }
    return unified, metadata


def map_ids_to_elk(hit: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = hit.get("_source", {})
    flat = flatten_dict(source)
    uri_value = build_uri(flat)
    if not uri_value:
        signature = str(coalesce(flat, "rule.name", "suricata.eve.alert.signature", "message", default="")).strip()
        app_proto = str(coalesce(flat, "network.application", "suricata.eve.app_proto", default="")).strip()
        uri_value = "" if not app_proto.lower().startswith("http") else signature

    unified = {
        "src_ip": str(coalesce(flat, "source.ip", "source.address", default="")),
        "dst_ip": str(coalesce(flat, "destination.ip", "destination.address", default="")),
        "src_port": as_int(coalesce(flat, "source.port", default=0)),
        "dst_port": as_int(coalesce(flat, "destination.port", default=0)),
        "protocol": protocol(flat) or str(coalesce(flat, "suricata.eve.proto", default="")).upper(),
        "bytes": network_bytes(flat),
        "packets": network_packets(flat),
        "duration": event_duration_seconds(flat),
        "http_method": http_method(flat),
        "uri": uri_value,
        "label": 0,
    }
    metadata = {
        "@timestamp": source.get("@timestamp", ""),
        "source_type": "ids_to_elk",
        "event_action": str(coalesce(flat, "event.kind", "event.action", default="")),
        "event_reason": str(coalesce(flat, "message", default="")),
        "rule_name": str(coalesce(flat, "rule.name", "suricata.eve.alert.signature", default="")),
        "severity": as_int(coalesce(flat, "event.severity", "suricata.eve.alert.severity", default=0)),
        "source_index": hit.get("_index", ""),
        "source_id": hit.get("_id", ""),
    }
    return unified, metadata


def risk_level(probability: float) -> str:
    if probability >= 0.85:
        return "high"
    if probability >= 0.5:
        return "medium"
    if probability >= 0.2:
        return "low"
    return "benign"


def append_ndjson(path: Path, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def truncate_text(value: str, max_length: int = 180) -> str:
    text = str(value or "").strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def should_send_telegram(record: dict[str, Any]) -> bool:
    probability = float(record["ml"]["malicious_probability"])
    alert = bool(record["ml"]["alert"])
    if TELEGRAM_SEND_ONLY_ALERTS and not alert:
        return False
    return probability >= TELEGRAM_MIN_PROBABILITY


def format_telegram_message(record: dict[str, Any]) -> str:
    network_event = record["network_event"]
    event_context = record["event_context"]
    ml = record["ml"]

    src = f'{network_event["src_ip"]}:{network_event["src_port"]}'
    dst = f'{network_event["dst_ip"]}:{network_event["dst_port"]}'
    uri = truncate_text(network_event.get("uri", ""))
    reason = truncate_text(event_context.get("reason", ""))
    rule_name = truncate_text(event_context.get("rule_name", ""))

    lines = [
        f"<b>{escape(TELEGRAM_MESSAGE_PREFIX)}</b>",
        f"Time: <code>{escape(str(record.get('@timestamp', '')))}</code>",
        f"Source: <code>{escape(str(record.get('source_type', '')))}</code>",
        f"Risk: <b>{escape(str(ml.get('risk_level', ''))).upper()}</b>",
        f"Score: <code>{float(ml.get('malicious_probability', 0.0)):.4f}</code>",
        f"Path: <code>{escape(src)}</code> -> <code>{escape(dst)}</code>",
        f"Protocol: <code>{escape(str(network_event.get('protocol', '')))}</code>",
    ]

    if network_event.get("http_method"):
        lines.append(f"Method: <code>{escape(str(network_event['http_method']))}</code>")
    if uri:
        lines.append(f"URI: <code>{escape(uri)}</code>")
    if rule_name:
        lines.append(f"Rule: <code>{escape(rule_name)}</code>")
    if reason:
        lines.append(f"Reason: <code>{escape(reason)}</code>")

    lines.append(
        f"Ref: <code>{escape(str(record['source_ref'].get('index', '')))}</code> / <code>{escape(str(record['source_ref'].get('id', '')))}</code>"
    )
    return "\n".join(lines)


def send_telegram_message(message: str) -> None:
    if not TELEGRAM_ENABLED:
        return

    payload = json.dumps(
        {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
    ).encode("utf-8")
    request = Request(
        url=f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=TELEGRAM_TIMEOUT_SECONDS) as response:
        response.read()


def send_telegram_alerts(records: list[dict[str, Any]]) -> None:
    if not TELEGRAM_ENABLED:
        return

    for record in records:
        if not should_send_telegram(record):
            continue
        try:
            send_telegram_message(format_telegram_message(record))
        except URLError as exc:
            print(f"[!] telegram error: {exc}")
        except Exception as exc:
            print(f"[!] telegram error: {exc}")


def fetch_new_hits(es: Elasticsearch, index: str, query: dict[str, Any], last_sort: list[Any] | None) -> tuple[list[dict[str, Any]], list[Any] | None]:
    body = dict(query)
    if last_sort is not None:
        body["search_after"] = last_sort

    response = es.search(index=index, body=body)
    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        return [], last_sort
    return hits, hits[-1]["sort"]


def fetch_latest_sort(es: Elasticsearch, index: str, query: dict[str, Any]) -> list[Any] | None:
    body = dict(query)
    body["size"] = 1
    body["sort"] = [{"@timestamp": "desc"}, {"_id": "desc"}]
    response = es.search(index=index, body=body)
    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        return None
    return hits[0].get("sort")


def index_predictions(es: Elasticsearch, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    actions = []
    for record in records:
        if INDEX_ONLY_ALERTS and not bool(record["ml"]["alert"]):
            continue
        actions.append({"_index": OUTPUT_INDEX, "_source": record})
    if actions:
        bulk(es, actions, refresh=False)


def score_hits(
    predictor: CybersecurityPredictor,
    hits: list[dict[str, Any]],
    mapper: Callable[[dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]],
) -> list[dict[str, Any]]:
    unified_records: list[dict[str, Any]] = []
    metadata_records: list[dict[str, Any]] = []
    original_records: list[dict[str, Any]] = []

    for hit in hits:
        unified_record, metadata = mapper(hit)
        unified_records.append(unified_record)
        metadata_records.append(metadata)
        original_records.append(hit.get("_source", {}))

    scored = predictor.predict_frame(pd.DataFrame(unified_records))
    output_records: list[dict[str, Any]] = []

    for original, unified, metadata, result in zip(original_records, unified_records, metadata_records, scored):
        probability = float(result["malicious_probability"])
        prediction = int(result["prediction"])
        output_records.append(
            {
                "@timestamp": metadata["@timestamp"],
                "source_type": metadata["source_type"],
                "source_ref": {
                    "index": metadata["source_index"],
                    "id": metadata["source_id"],
                },
                "network_event": {
                    "src_ip": unified["src_ip"],
                    "dst_ip": unified["dst_ip"],
                    "src_port": unified["src_port"],
                    "dst_port": unified["dst_port"],
                    "protocol": unified["protocol"],
                    "bytes": unified["bytes"],
                    "packets": unified["packets"],
                    "duration": unified["duration"],
                    "http_method": unified["http_method"],
                    "uri": unified["uri"],
                },
                "event_context": {
                    "action": metadata.get("event_action", ""),
                    "reason": metadata.get("event_reason", ""),
                    "rule_name": metadata.get("rule_name", ""),
                    "severity": metadata.get("severity", 0),
                },
                "ml": {
                    "prediction": prediction,
                    "malicious_probability": probability,
                    "risk_level": risk_level(probability),
                    "alert": bool(prediction == 1),
                    "selected_view": result["selected_view"],
                    "model_family": "xgboost_or_random_forest_runtime",
                },
                "original_event": original,
            }
        )
    return output_records


def main() -> None:
    if not ES_VERIFY_CERTS:
        disable_warnings(InsecureRequestWarning)

    es = Elasticsearch(
        ES_URL,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=ES_VERIFY_CERTS,
        request_timeout=30,
    )
    predictor = CybersecurityPredictor(artifact_dir=ARTIFACT_DIR)

    mapper_by_source: dict[str, Callable[[dict[str, Any]], tuple[dict[str, Any], dict[str, Any]]]] = {
        "pfelkfw": map_pfelkfw,
        "ids_to_elk": map_ids_to_elk,
    }

    last_sort_map: dict[str, list[Any] | None] = {source_name: None for source_name in SOURCES}
    if START_FROM_LATEST:
        for source_name, config in SOURCES.items():
            try:
                last_sort_map[source_name] = fetch_latest_sort(es, config["index"], config["query"])
            except Exception as exc:
                print(f"[!] bootstrap {source_name} error: {exc}")

    print("[+] Realtime ELK predictor started")
    print(f"[+] Write back to Elasticsearch: {OUTPUT_TO_ES}")
    if OUTPUT_TO_ES:
        print(f"[+] Output index: {OUTPUT_INDEX}")
    print(f"[+] Save local NDJSON: {SAVE_LOCAL_OUTPUT}")
    print(f"[+] Poll interval: {POLL_INTERVAL_SECONDS} seconds")
    print(f"[+] Telegram enabled: {TELEGRAM_ENABLED}")

    while True:
        for source_name, config in SOURCES.items():
            try:
                hits, new_last_sort = fetch_new_hits(
                    es=es,
                    index=config["index"],
                    query=config["query"],
                    last_sort=last_sort_map[source_name],
                )
                if not hits:
                    continue

                records = score_hits(
                    predictor=predictor,
                    hits=hits,
                    mapper=mapper_by_source[source_name],
                )
                if SAVE_LOCAL_OUTPUT:
                    append_ndjson(OUTPUT_DIR / "predictions.ndjson", records)

                if OUTPUT_TO_ES:
                    index_predictions(es, records)

                send_telegram_alerts(records)

                for record in records:
                    print(json.dumps(record, ensure_ascii=False))

                last_sort_map[source_name] = new_last_sort
            except Exception as exc:
                print(f"[!] {source_name} error: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
