import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import DATA_FILE, SURICATA_EVE_PATH, SURICATA_STATE_FILE


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def load_events() -> list[dict[str, Any]]:
    if not Path(DATA_FILE).exists():
        return []

    rows: list[dict[str, Any]] = []
    with Path(DATA_FILE).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    return rows


def get_recent_events(limit: int = 20) -> list[dict[str, Any]]:
    events = load_events()
    events = sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)
    return events[:limit]


def get_live_status() -> dict[str, Any]:
    events = load_events()
    now = datetime.now(timezone.utc)
    five_minutes_ago = now - timedelta(minutes=5)

    recent_count = 0
    latest_timestamp = None

    for event in events:
        ts = _parse_ts(event.get("timestamp"))
        if ts:
            if latest_timestamp is None or ts > latest_timestamp:
                latest_timestamp = ts
            if ts >= five_minutes_ago:
                recent_count += 1

    watcher_state = {}
    if SURICATA_STATE_FILE.exists():
        try:
            watcher_state = json.loads(SURICATA_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            watcher_state = {}

    return {
        "backend_status": "online",
        "suricata_eve_exists": SURICATA_EVE_PATH.exists(),
        "suricata_state_exists": SURICATA_STATE_FILE.exists(),
        "suricata_state": watcher_state,
        "total_events": len(events),
        "events_last_5_minutes": recent_count,
        "latest_event_timestamp": latest_timestamp.isoformat() if latest_timestamp else None,
    }
