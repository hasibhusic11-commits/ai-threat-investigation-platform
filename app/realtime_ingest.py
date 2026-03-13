import json
import time
from pathlib import Path
from typing import Any

from app.config import DATA_FILE, SURICATA_EVE_PATH, SURICATA_STATE_FILE
from app.suricata_normalizer import parse_eve_line


def load_state() -> dict[str, Any]:
    if not SURICATA_STATE_FILE.exists():
        return {
            "offset": 0,
            "lines_processed": 0,
            "last_ingest_time": None,
            "status": "idle",
        }

    try:
        return json.loads(SURICATA_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {
            "offset": 0,
            "lines_processed": 0,
            "last_ingest_time": None,
            "status": "error_loading_state",
        }


def save_state(state: dict[str, Any]) -> None:
    SURICATA_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def append_normalized_event(event: dict[str, Any]) -> None:
    with DATA_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def process_new_lines() -> int:
    state = load_state()
    offset = int(state.get("offset", 0))

    if not SURICATA_EVE_PATH.exists():
        state["status"] = "eve_file_missing"
        save_state(state)
        return 0

    processed = 0

    with SURICATA_EVE_PATH.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)

        for line in f:
            normalized = parse_eve_line(line)
            if normalized:
                append_normalized_event(normalized)
                processed += 1

        new_offset = f.tell()

    state["offset"] = new_offset
    state["lines_processed"] = int(state.get("lines_processed", 0)) + processed
    state["last_ingest_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    state["status"] = "running"
    save_state(state)

    return processed


def run_realtime_pipeline(poll_interval: int = 2) -> None:
    print(f"Watching {SURICATA_EVE_PATH} for live Suricata events...")
    Path(DATA_FILE).parent.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            count = process_new_lines()
            if count:
                print(f"Ingested {count} new Suricata event(s)")
        except KeyboardInterrupt:
            state = load_state()
            state["status"] = "stopped"
            save_state(state)
            raise
        except Exception as exc:
            state = load_state()
            state["status"] = f"error: {exc}"
            save_state(state)
            print(f"Watcher error: {exc}")

        time.sleep(poll_interval)
