from __future__ import annotations

import json
import os
import time
from html import escape
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import pandas as pd
from elasticsearch import Elasticsearch
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from src.inference.predictor import CybersecurityPredictor

ES_URL = os.getenv("ES_URL", "https://127.0.0.1:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "changeme")
ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"

INDEX = os.getenv("IDS_INDEX", "filebeat-*")
ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", "artifacts"))
OUTPUT_FILE = Path(os.getenv("IDS_OUTPUT_FILE", "ids_live_one_by_one.ndjson"))
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "1"))
FETCH_BATCH_SIZE = int(os.getenv("IDS_FETCH_BATCH_SIZE", "100"))
START_FROM_LATEST = os.getenv("START_FROM_LATEST", "true").lower() == "true"
SAVE_LOCAL_OUTPUT = os.getenv("SAVE_LOCAL_OUTPUT", "true").lower() == "true"

ALERT_MODE = os.getenv("IDS_ALERT_MODE", "suricata_or_ml").strip().lower()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "true").lower() == "true" and bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
TELEGRAM_MIN_PROBABILITY = float(os.getenv("TELEGRAM_MIN_PROBABILITY", "0.50"))
TELEGRAM_TIMEOUT_SECONDS = float(os.getenv("TELEGRAM_TIMEOUT_SECONDS", "10"))
TELEGRAM_MESSAGE_PREFIX = os.getenv("TELEGRAM_MESSAGE_PREFIX", "IDS Alert").strip()

TIMESTAMP_SORT = [
    {
        "@timestamp": {
            "order": "asc",
            "format": "strict_date_optional_time_nanos",
        }
    }
]


def append_ndjson(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


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
        default=0.0,
    )
    duration = as_float(duration_value, 0.0)
    if duration > 1_000_000:
        return duration / 1_000_000_000.0
    return duration


def network_bytes(flat: dict[str, Any]) -> float:
    total_bytes = as_float(coalesce(flat, "network.bytes", default=0.0), 0.0)
    if total_bytes > 0:
        return total_bytes

    source_bytes = as_float(coalesce(flat, "source.bytes", "suricata.eve.flow.bytes_toserver", default=0.0), 0.0)
    destination_bytes = as_float(coalesce(flat, "destination.bytes", "suricata.eve.flow.bytes_toclient", default=0.0), 0.0)
    combined = source_bytes + destination_bytes
    return combined if combined > 0 else 0.0


def network_packets(flat: dict[str, Any]) -> float:
    total_packets = as_float(coalesce(flat, "network.packets", default=0.0), 0.0)
    if total_packets > 0:
        return total_packets

    source_packets = as_float(coalesce(flat, "source.packets", "suricata.eve.flow.pkts_toserver", default=0.0), 0.0)
    destination_packets = as_float(coalesce(flat, "destination.packets", "suricata.eve.flow.pkts_toclient", default=0.0), 0.0)
    combined = source_packets + destination_packets
    return combined if combined > 0 else 1.0


def build_uri(flat: dict[str, Any]) -> str:
    original = str(coalesce(flat, "url.original", default="")).strip()
    if original:
        return original

    path = str(
        coalesce(
            flat,
            "url.path",
            "http.request.path",
            "suricata.eve.http.url",
            default="",
        )
    ).strip()
    query = str(coalesce(flat, "url.query", "http.request.query", default="")).strip()
    if path and query:
        return f"{path}?{query}"
    if path:
        return path

    signature = str(coalesce(flat, "rule.name", "suricata.eve.alert.signature", default="")).strip()
    app_proto = str(coalesce(flat, "network.application", "suricata.eve.app_proto", default="")).strip().lower()
    if signature and app_proto.startswith("http"):
        return signature
    return ""


def http_method(flat: dict[str, Any]) -> str:
    return str(
        coalesce(
            flat,
            "http.request.method",
            "http.method",
            "suricata.eve.http.http_method",
            default="",
        )
    ).upper()


def protocol(flat: dict[str, Any]) -> str:
    return str(coalesce(flat, "network.protocol", "network.transport", "suricata.eve.proto", default="")).upper()


def risk_level(probability: float) -> str:
    if probability >= 0.85:
        return "high"
    if probability >= 0.5:
        return "medium"
    if probability >= 0.2:
        return "low"
    return "benign"


def build_query(last_timestamp: str | None) -> dict[str, Any]:
    query: dict[str, Any] = {
        "size": FETCH_BATCH_SIZE,
        "_source": True,
        "sort": TIMESTAMP_SORT,
        "track_total_hits": False,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.module": "suricata"}},
                    {"term": {"event.kind": "alert"}},
                ]
            }
        },
    }

    if last_timestamp is not None:
        query["query"]["bool"]["filter"] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": last_timestamp,
                    }
                }
            }
        ]

    return query


def fetch_latest_cursor(es: Elasticsearch) -> dict[str, Any]:
    body = build_query(last_timestamp=None)
    body["size"] = 1
    body["sort"] = [{"@timestamp": {"order": "desc", "format": "strict_date_optional_time_nanos"}}]
    response = es.search(index=INDEX, body=body)
    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        return {"last_timestamp": None, "seen_ids": []}

    hit = hits[0]
    timestamp = str(hit.get("_source", {}).get("@timestamp", "") or "")
    hit_key = f'{hit.get("_index", "")}:{hit.get("_id", "")}'
    return {"last_timestamp": timestamp, "seen_ids": [hit_key]}


def deduplicate_hits(hits: list[dict[str, Any]], cursor: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    last_timestamp = cursor.get("last_timestamp")
    seen_ids = set(cursor.get("seen_ids", []))
    accepted_hits: list[dict[str, Any]] = []

    newest_timestamp = last_timestamp
    newest_seen_ids = set(seen_ids)

    for hit in hits:
        timestamp = str(hit.get("_source", {}).get("@timestamp", "") or "")
        hit_key = f'{hit.get("_index", "")}:{hit.get("_id", "")}'

        if last_timestamp and timestamp == last_timestamp and hit_key in seen_ids:
            continue

        accepted_hits.append(hit)

        if not newest_timestamp or timestamp > newest_timestamp:
            newest_timestamp = timestamp
            newest_seen_ids = {hit_key}
        elif timestamp == newest_timestamp:
            newest_seen_ids.add(hit_key)

    new_cursor = {
        "last_timestamp": newest_timestamp,
        "seen_ids": sorted(newest_seen_ids),
    }
    return accepted_hits, new_cursor


def map_suricata_hit(hit: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = hit.get("_source", {})
    flat = flatten_dict(source)

    unified = {
        "src_ip": str(coalesce(flat, "source.ip", "source.address", default="")),
        "dst_ip": str(coalesce(flat, "destination.ip", "destination.address", default="")),
        "src_port": as_int(coalesce(flat, "source.port", default=0)),
        "dst_port": as_int(coalesce(flat, "destination.port", default=0)),
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
        "source_index": hit.get("_index", ""),
        "source_id": hit.get("_id", ""),
        "signature": str(coalesce(flat, "rule.name", "suricata.eve.alert.signature", default="")),
        "severity": as_int(coalesce(flat, "event.severity", "suricata.eve.alert.severity", default=0)),
        "category": str(coalesce(flat, "rule.category", "suricata.eve.alert.category", default="")),
        "message": str(coalesce(flat, "message", default="")),
        "action": str(coalesce(flat, "event.action", "event.kind", default="alert")),
        "original_event": source,
    }
    return unified, metadata


def decide_alert(prediction: int, probability: float) -> tuple[bool, str]:
    if ALERT_MODE == "ml_only":
        return bool(prediction == 1), "ml_prediction"
    if ALERT_MODE == "suricata_only":
        return True, "suricata_alert"
    if prediction == 1:
        return True, "suricata_alert_and_ml"
    return True, "suricata_alert"


def truncate_text(value: str, max_length: int = 180) -> str:
    text = str(value or "").strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def format_telegram_message(record: dict[str, Any]) -> str:
    network_event = record["network_event"]
    suricata = record["suricata"]
    ml = record["ml"]
    alert = record["alert"]

    src = f'{network_event["src_ip"]}:{network_event["src_port"]}'
    dst = f'{network_event["dst_ip"]}:{network_event["dst_port"]}'

    lines = [
        f"<b>{escape(TELEGRAM_MESSAGE_PREFIX)}</b>",
        f"Time: <code>{escape(str(record.get('@timestamp', '')))}</code>",
        f"Reason: <code>{escape(str(alert.get('reason', '')))}</code>",
        f"Risk: <b>{escape(str(ml.get('risk_level', ''))).upper()}</b>",
        f"Score: <code>{float(ml.get('malicious_probability', 0.0)):.4f}</code>",
        f"Path: <code>{escape(src)}</code> -> <code>{escape(dst)}</code>",
        f"Protocol: <code>{escape(str(network_event.get('protocol', '')))}</code>",
    ]

    signature = truncate_text(suricata.get("signature", ""))
    category = truncate_text(suricata.get("category", ""))
    uri = truncate_text(network_event.get("uri", ""))
    if signature:
        lines.append(f"Signature: <code>{escape(signature)}</code>")
    if category:
        lines.append(f"Category: <code>{escape(category)}</code>")
    if uri:
        lines.append(f"URI: <code>{escape(uri)}</code>")

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


def maybe_send_telegram(record: dict[str, Any]) -> None:
    if not TELEGRAM_ENABLED:
        return
    if not bool(record["alert"]["triggered"]):
        return
    if float(record["ml"]["malicious_probability"]) < TELEGRAM_MIN_PROBABILITY and ALERT_MODE == "ml_only":
        return

    try:
        send_telegram_message(format_telegram_message(record))
    except URLError as exc:
        print(f"[!] telegram error: {exc}")
    except Exception as exc:
        print(f"[!] telegram error: {exc}")


def score_hit(predictor: CybersecurityPredictor, hit: dict[str, Any]) -> dict[str, Any]:
    unified, metadata = map_suricata_hit(hit)
    result = predictor.predict_frame(pd.DataFrame([unified]))[0]

    probability = float(result["malicious_probability"])
    prediction = int(result["prediction"])
    triggered, reason = decide_alert(prediction, probability)

    return {
        "@timestamp": metadata["@timestamp"],
        "source_type": "ids_to_elk",
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
        "suricata": {
            "signature": metadata["signature"],
            "severity": metadata["severity"],
            "category": metadata["category"],
            "action": metadata["action"],
            "message": metadata["message"],
        },
        "ml": {
            "prediction": prediction,
            "malicious_probability": probability,
            "risk_level": risk_level(probability),
            "selected_view": result["selected_view"],
            "model_family": "xgboost_or_random_forest_runtime",
        },
        "alert": {
            "triggered": triggered,
            "reason": reason,
            "mode": ALERT_MODE,
        },
        "original_event": metadata["original_event"],
    }


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

    cursor = {"last_timestamp": None, "seen_ids": []}
    if START_FROM_LATEST:
        try:
            cursor = fetch_latest_cursor(es)
        except Exception as exc:
            print(f"[!] bootstrap ids_to_elk error: {exc}")

    print("[+] IDS realtime 1:1 with model started")
    print(f"[+] Alert mode: {ALERT_MODE}")
    print(f"[+] Save local NDJSON: {SAVE_LOCAL_OUTPUT}")
    print(f"[+] Telegram enabled: {TELEGRAM_ENABLED}")

    while True:
        try:
            query = build_query(cursor.get("last_timestamp"))
            response = es.search(index=INDEX, body=query)
            hits = response.get("hits", {}).get("hits", [])
            hits, cursor = deduplicate_hits(hits, cursor)

            for hit in hits:
                record = score_hit(predictor, hit)
                print(json.dumps(record, ensure_ascii=False))

                if SAVE_LOCAL_OUTPUT:
                    append_ndjson(OUTPUT_FILE, record)

                maybe_send_telegram(record)

        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
            break
        except Exception as exc:
            print(f"[!] IDS realtime error: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
