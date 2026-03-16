import json
from pathlib import Path
from typing import Any

from app.config import DATA_FILE


def load_normalized_events() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    path = Path(DATA_FILE)
    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return rows
