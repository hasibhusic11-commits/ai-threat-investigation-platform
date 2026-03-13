import hashlib
from typing import Any


SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


def stable_event_id(*parts: str) -> int:
    raw = "|".join(parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def normalize_suricata_alert(doc: dict[str, Any]) -> dict[str, Any] | None:
    if doc.get("event_type") != "alert":
        return None

    alert = doc.get("alert", {})
    timestamp = doc.get("timestamp")
    src_ip = doc.get("src_ip")
    dest_ip = doc.get("dest_ip")
    src_port = doc.get("src_port")
    dest_port = doc.get("dest_port")
    proto = doc.get("proto")
    signature = alert.get("signature", "Suricata alert")
    category = alert.get("category", "unknown")
    severity_num = alert.get("severity", 3)

    severity = SEVERITY_MAP.get(severity_num, "medium")

    event_text = (
        f"Suricata alert: {signature}. "
        f"Category: {category}. "
        f"Source {src_ip}:{src_port} -> Destination {dest_ip}:{dest_port} over {proto}."
    )

    event_id = stable_event_id(
        str(timestamp),
        str(src_ip),
        str(dest_ip),
        str(src_port),
        str(dest_port),
        str(signature),
    )

    host = dest_ip or "network-sensor"

    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_text": event_text,
        "source": "suricata",
        "severity": severity,
        "event_type": "network_alert",
        "host": host,
        "username": None,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "proto": proto,
        "signature": signature,
        "category": category,
    }
