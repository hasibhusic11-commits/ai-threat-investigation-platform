import json
import time
from pathlib import Path
from typing import Any

from app.config import DATA_FILE, SURICATA_EVE_PATH, SURICATA_STATE_FILE
from app.ingest import upsert_single_event
from app.logging_config import setup_logger
from pipelines.suricata_parser import parse_suricata_line

logger = setup_logger("live-ingest-service")


def ensure_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def append_event_to_store(event: dict[str, Any]) -> None:
    ensure_file(DATA_FILE)
    with DATA_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def read_state() -> dict[str, Any]:
    ensure_file(SURICATA_STATE_FILE)
    try:
        text = SURICATA_STATE_FILE.read_text(encoding="utf-8").strip()
        if not text:
            return {"offset": 0}
        return json.loads(text)
    except Exception:
        return {"offset": 0}


def write_state(state: dict[str, Any]) -> None:
    SURICATA_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


def watch_suricata_eve(eve_path: Path | None = None, poll_interval: float = 1.0) -> None:
    source = eve_path or SURICATA_EVE_PATH
    ensure_file(source)

    state = read_state()
    offset = state.get("offset", 0)
    seen_ids: set[int] = set()

    logger.info(f"Watching Suricata EVE file: {source}")

    with source.open("r", encoding="utf-8") as f:
        f.seek(offset)

        while True:
            line = f.readline()

            if not line:
                offset = f.tell()
                write_state({"offset": offset})
                time.sleep(poll_interval)
                continue

            offset = f.tell()
            event = parse_suricata_line(line)

            if not event:
                write_state({"offset": offset})
                continue

            event_id = int(event["id"])
            if event_id in seen_ids:
                write_state({"offset": offset})
                continue

            seen_ids.add(event_id)

            try:
                append_event_to_store(event)
                enriched = upsert_single_event(event)
                logger.info(
                    f"Ingested live Suricata event id={event_id} "
                    f"src={enriched.get('src_ip')} dest={enriched.get('dest_ip')} "
                    f"risk={enriched.get('risk_score')} signature={event.get('signature')}"
                )
            except Exception as exc:
                logger.error(f"Failed to ingest event id={event_id}: {exc}")

            write_state({"offset": offset})
