import json
import time
from pathlib import Path

from app.config import DATA_FILE, SURICATA_EVE_PATH
from app.suricata_normalizer import parse_eve_line


def load_state(state_file: Path) -> dict:
    if state_file.exists():
        try:
            return json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"offset": 0, "status": "idle"}


def save_state(state_file: Path, state: dict) -> None:
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")


def append_normalized_event(event: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with DATA_FILE.open("a", encoding="utf-8") as f:
      f.write(json.dumps(event) + "\n")


def process_new_lines(eve_path: Path, offset: int) -> tuple[int, int]:
    if not eve_path.exists():
        return offset, 0

    processed = 0

    with eve_path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)

        while True:
            start_pos = f.tell()
            line = f.readline()

            if not line:
                break

            stripped = line.strip()

            if not stripped:
                offset = f.tell()
                continue

            # If the line does not look like a complete JSON object yet,
            # do not advance permanently past it. Wait for the next poll.
            if not (stripped.startswith("{") and stripped.endswith("}")):
                f.seek(start_pos)
                break

            try:
                normalized = parse_eve_line(stripped)
                if normalized:
                    append_normalized_event(normalized)
                    processed += 1
                offset = f.tell()
            except json.JSONDecodeError:
                # Partial/corrupt line: rewind and wait for next poll
                f.seek(start_pos)
                break
            except Exception:
                # Skip truly bad lines so one broken entry doesn't kill the watcher
                offset = f.tell()
                continue

    return offset, processed


def run_realtime_pipeline(poll_interval: int = 2, state_file: Path | None = None) -> None:
    if state_file is None:
        state_file = SURICATA_EVE_PATH.parent.parent / "suricata_state.json"

    state = load_state(state_file)
    offset = int(state.get("offset", 0))

    print(f"Watching {SURICATA_EVE_PATH} for live Suricata events...")

    while True:
        try:
            offset, processed = process_new_lines(SURICATA_EVE_PATH, offset)
            state["offset"] = offset
            state["status"] = "running"
            state["last_processed"] = processed
            save_state(state_file, state)
        except KeyboardInterrupt:
            state["status"] = "stopped"
            save_state(state_file, state)
            raise
        except Exception as exc:
            state["status"] = f"error: {exc}"
            save_state(state_file, state)
            print(f"Realtime ingest error: {exc}")

        time.sleep(poll_interval)
