import json
from datetime import datetime, timezone
from typing import Any


PRIVATE_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "127.",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    return ip.startswith(PRIVATE_PREFIXES)


def event_type_to_internal(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "alert":
        signature = (payload.get("alert") or {}).get("signature", "").lower()

        if "ssh" in signature and "scan" in signature:
            return "reconnaissance"
        if "brute" in signature or "authentication" in signature or "login" in signature:
            return "authentication"
        if "command" in signature or "shell" in signature:
            return "execution"
        if "exfil" in signature:
            return "exfiltration"

        return "alert"

    if event_type == "dns":
        return "dns"
    if event_type == "http":
        return "http"
    if event_type == "flow":
        return "network_flow"

    return event_type


def severity_from_suricata(payload: dict[str, Any]) -> str:
    alert = payload.get("alert") or {}
    sev = alert.get("severity")

    if sev == 1:
        return "critical"
    if sev == 2:
        return "high"
    if sev == 3:
        return "medium"
    if sev == 4:
        return "low"

    return "medium"


def quick_risk_score(payload: dict[str, Any]) -> int:
    event_type = payload.get("event_type")
    src_ip = payload.get("src_ip")
    dest_ip = payload.get("dest_ip")

    score = 0

    if event_type == "alert":
        score += 35

    if event_type == "dns":
        score += 10

    if event_type == "http":
        score += 10

    if event_type == "flow":
        score += 5

    if src_ip and not is_private_ip(src_ip):
        score += 15

    if dest_ip and not is_private_ip(dest_ip):
        score += 10

    signature = ((payload.get("alert") or {}).get("signature") or "").lower()

    if "scan" in signature:
        score += 15
    if "ssh" in signature:
        score += 10
    if "brute" in signature:
        score += 20
    if "exfil" in signature:
        score += 30
    if "command" in signature or "shell" in signature:
        score += 20

    return min(score, 100)


def build_event_text(payload: dict[str, Any]) -> str:
    event_type = payload.get("event_type")
    src_ip = payload.get("src_ip")
    dest_ip = payload.get("dest_ip")
    proto = payload.get("proto")

    if event_type == "alert":
        alert = payload.get("alert") or {}
        return alert.get("signature") or f"Suricata alert from {src_ip} to {dest_ip}"

    if event_type == "dns":
        dns = payload.get("dns") or {}
        rrname = dns.get("rrname", "unknown-domain")
        return f"DNS query for {rrname} from {src_ip}"

    if event_type == "http":
        http = payload.get("http") or {}
        hostname = http.get("hostname", "unknown-host")
        url = http.get("url", "/")
        return f"HTTP request to {hostname}{url} from {src_ip}"

    if event_type == "flow":
        return f"Network flow {src_ip} -> {dest_ip} over {proto or 'unknown-proto'}"

    return f"Suricata {event_type} event from {src_ip} to {dest_ip}"


def normalize_suricata_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    event_type = payload.get("event_type")
    if not event_type:
        return None

    # Keep only event types useful for this platform
    if event_type not in {"alert", "dns", "http", "flow"}:
        return None

    src_ip = payload.get("src_ip")
    dest_ip = payload.get("dest_ip")

    host = None
    if dest_ip and is_private_ip(dest_ip):
        host = dest_ip
    elif src_ip and is_private_ip(src_ip):
        host = src_ip

    normalized = {
        "timestamp": payload.get("timestamp") or now_iso(),
        "source": "suricata",
        "source_type": "suricata_eve",
        "event_type": event_type_to_internal(event_type, payload),
        "original_event_type": event_type,
        "event_text": build_event_text(payload),
        "severity": severity_from_suricata(payload),
        "risk_score": quick_risk_score(payload),
        "host": host,
        "username": None,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": payload.get("src_port"),
        "dest_port": payload.get("dest_port"),
        "proto": payload.get("proto"),
        "signature": ((payload.get("alert") or {}).get("signature") if payload.get("alert") else None),
        "mitre_matches": [],
        "threat_intel": {
            "reputation": "suspicious" if src_ip and not is_private_ip(src_ip) else "unknown"
        },
        "raw": payload,
    }

    return normalized


def parse_eve_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    try:
        payload = json.loads(line)
    except Exception:
        return None

    return normalize_suricata_event(payload)
