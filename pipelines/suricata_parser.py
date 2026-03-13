import json
from typing import Any

from app.normalizer import normalize_suricata_alert


def parse_suricata_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None

    return normalize_suricata_alert(doc)
