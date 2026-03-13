from collections import defaultdict
from typing import Any


def _ensure_ids(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []

    for idx, event in enumerate(events, start=1):
        copy_event = dict(event)

        if "id" not in copy_event or copy_event["id"] in (None, ""):
            copy_event["id"] = idx

        normalized.append(copy_event)

    return normalized


def _shared_indicators(a: dict[str, Any], b: dict[str, Any]) -> bool:
    a_src = a.get("src_ip")
    a_dst = a.get("dest_ip")
    a_host = a.get("host")
    a_user = a.get("username")

    b_src = b.get("src_ip")
    b_dst = b.get("dest_ip")
    b_host = b.get("host")
    b_user = b.get("username")

    if a_src and (a_src == b_src or a_src == b_dst):
        return True
    if a_dst and (a_dst == b_src or a_dst == b_dst):
        return True
    if a_host and a_host == b_host:
        return True
    if a_user and a_user == b_user:
        return True

    return False


def _event_time(event: dict[str, Any]) -> str:
    return event.get("timestamp", "")


def build_attack_chains(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    if not events:
        return []

    events = _ensure_ids(events)
    events = sorted(events, key=_event_time)

    adjacency: dict[int, set[int]] = defaultdict(set)
    id_to_event: dict[int, dict[str, Any]] = {}

    for event in events:
        event_id = int(event["id"])
        id_to_event[event_id] = event
        adjacency[event_id]

    for i, a in enumerate(events):
        for j in range(i + 1, len(events)):
            b = events[j]

            if _shared_indicators(a, b):
                a_id = int(a["id"])
                b_id = int(b["id"])
                adjacency[a_id].add(b_id)
                adjacency[b_id].add(a_id)

    visited = set()
    chains: list[list[dict[str, Any]]] = []

    for event in events:
        start_id = int(event["id"])
        if start_id in visited:
            continue

        stack = [start_id]
        component_ids = []

        while stack:
            current = stack.pop()
            if current in visited:
                continue

            visited.add(current)
            component_ids.append(current)

            for neighbor in adjacency[current]:
                if neighbor not in visited:
                    stack.append(neighbor)

        chain_events = [id_to_event[event_id] for event_id in component_ids]
        chain_events = sorted(chain_events, key=_event_time)
        chains.append(chain_events)

    chains.sort(key=len, reverse=True)
    return chains
