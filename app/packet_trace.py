from collections import defaultdict
from typing import Any

from app.live_status import load_events


def build_packet_flows() -> list[dict[str, Any]]:
    events = load_events()
    flows: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        src = event.get("src_ip")
        dst = event.get("dest_ip")

        if not src or not dst:
            continue

        key = f"{src}->{dst}"

        flows[key].append(
            {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "event_type": event.get("event_type"),
                "event_text": event.get("event_text"),
                "risk_score": event.get("risk_score"),
                "source": event.get("source"),
                "mitre_matches": event.get("mitre_matches", []),
            }
        )

    output: list[dict[str, Any]] = []

    for flow, items in flows.items():
        src, dst = flow.split("->", 1)
        sorted_items = sorted(items, key=lambda x: x.get("timestamp") or "")

        max_risk = 0
        for item in sorted_items:
            risk = item.get("risk_score", 0) or 0
            if isinstance(risk, (int, float)) and risk > max_risk:
                max_risk = risk

        output.append(
            {
                "src_ip": src,
                "dest_ip": dst,
                "event_count": len(sorted_items),
                "max_risk_score": max_risk,
                "timeline": sorted_items,
            }
        )

    output.sort(key=lambda x: (x["max_risk_score"], x["event_count"]), reverse=True)
    return output


def trace_ip(ip: str) -> list[dict[str, Any]]:
    flows = build_packet_flows()
    related = []

    for flow in flows:
        if flow["src_ip"] == ip or flow["dest_ip"] == ip:
            related.append(flow)

    return related


def get_packet_graph(ip: str | None = None) -> dict[str, Any]:
    flows = trace_ip(ip) if ip else build_packet_flows()

    node_map: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def ensure_node(node_id: str) -> None:
        if node_id not in node_map:
            node_map[node_id] = {
                "id": node_id,
                "label": node_id,
                "type": "ip",
            }

    for flow in flows:
        src = flow["src_ip"]
        dst = flow["dest_ip"]

        ensure_node(src)
        ensure_node(dst)

        edges.append(
            {
                "id": f"{src}->{dst}",
                "source": src,
                "target": dst,
                "label": f"{flow['event_count']} events",
                "risk_score": flow.get("max_risk_score", 0),
            }
        )

    return {
        "nodes": list(node_map.values()),
        "edges": edges,
    }
