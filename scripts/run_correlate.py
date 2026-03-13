import json
from pathlib import Path

from app.config import DATA_FILE
from app.correlation import build_attack_chains


def load_logs(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


if __name__ == "__main__":
    events = load_logs(DATA_FILE)
    chains = build_attack_chains(events)

    if not chains:
        print("No correlated attack chains found.")
    else:
        print("\nDetected attack chains:\n")
        for chain in chains:
            print(f"Chain ID: {chain['chain_id']}")
            print(f"Hosts: {chain['hosts']}")
            print(f"Users: {chain['usernames']}")
            print(f"Event Count: {chain['event_count']}")
            print("Events:")
            for event in chain["events"]:
                print(f"  - [{event['timestamp']}] {event['event_type']} | {event['event_text']}")
            print("-" * 80)
