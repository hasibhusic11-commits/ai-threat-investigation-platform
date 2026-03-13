import json
from pathlib import Path

from app.config import DATA_FILE
from app.correlation import build_attack_chains
from app.summarizer import summarize_chain


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
        print("\nIncident summaries:\n")
        for chain in chains:
            summary = summarize_chain(chain)
            print(f"Chain ID: {chain['chain_id']}")
            print(json.dumps(summary, indent=2))
            print("-" * 80)
