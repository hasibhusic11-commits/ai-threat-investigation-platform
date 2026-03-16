from collections import defaultdict
from datetime import datetime
from typing import Any

from app.api_utils import load_normalized_events


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.min


def _incident_title(events: list[dict[str, Any]]) -> str:
    scenario = events[0].get("scenario")
    if scenario:
        return scenario

    event_types = sorted(set(e.get("event_type", "unknown") for e in events))
    if len(event_types) == 1:
        return f"{event_types[0].title()} Activity"
    return "Correlated Suspicious Activity"


def _build_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "event_count": len(events),
        "event_types": sorted(set(e.get("event_type", "unknown") for e in events)),
        "max_risk_score": max((e.get("risk_score", 0) for e in events), default=0),
        "scenarios": sorted(set(e.get("scenario", "unknown") for e in events)),
    }


def _build_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline = []
    for e in sorted(events, key=lambda x: _parse_ts(x.get("timestamp", ""))):
        timeline.append(
            {
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "src_ip": e.get("src_ip"),
                "dest_ip": e.get("dest_ip"),
                "host": e.get("host"),
                "username": e.get("username"),
                "risk_score": e.get("risk_score", 0),
            }
        )
    return timeline


def _is_suspicious_ip(ip: str | None) -> bool:
    if not ip:
        return False
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")
    return not ip.startswith(private_prefixes)


def build_incidents() -> list[dict[str, Any]]:
    events = load_normalized_events()

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        scenario = event.get("scenario", "unknown")
        host = event.get("host", "unknown")
        user = event.get("username", "unknown")
        key = (scenario, host, user)
        grouped[key].append(event)

    incidents: list[dict[str, Any]] = []

    for idx, ((scenario, host, user), grouped_events) in enumerate(grouped.items(), start=1):
        grouped_events = sorted(grouped_events, key=lambda x: _parse_ts(x.get("timestamp", "")))

        suspicious_ips = sorted(
            {
                ip
                for e in grouped_events
                for ip in [e.get("src_ip"), e.get("dest_ip")]
                if _is_suspicious_ip(ip)
            }
        )

        mitre_techniques = []
        seen_techniques = set()
        for e in grouped_events:
            for match in e.get("mitre_matches", []):
                tech_id = match.get("technique", "UNKNOWN")
                if tech_id not in seen_techniques:
                    mitre_techniques.append(match)
                    seen_techniques.add(tech_id)

        incidents.append(
            {
                "incident_id": f"inc-{idx:03d}",
                "title": _incident_title(grouped_events),
                "scenario": scenario,
                "hosts": sorted({e.get("host") for e in grouped_events if e.get("host")}),
                "users": sorted({e.get("username") for e in grouped_events if e.get("username")}),
                "suspicious_ips": suspicious_ips,
                "event_count": len(grouped_events),
                "max_risk_score": max((e.get("risk_score", 0) for e in grouped_events), default=0),
                "mitre_techniques": mitre_techniques,
                "summary": _build_summary(grouped_events),
                "timeline": _build_timeline(grouped_events),
                "events": grouped_events,
                "first_seen": grouped_events[0].get("timestamp") if grouped_events else None,
                "last_seen": grouped_events[-1].get("timestamp") if grouped_events else None,
                "status": "open",
            }
        )

    incidents.sort(
        key=lambda x: (x.get("max_risk_score", 0), x.get("last_seen") or ""),
        reverse=True,
    )
    return incidents


def get_incident_by_id(incident_id: str) -> dict[str, Any] | None:
    for incident in build_incidents():
        if incident.get("incident_id") == incident_id:
            return incident
    return None


def filter_incidents(
    incidents: list[dict[str, Any]],
    min_risk_score: int | None = None,
    host: str | None = None,
    technique: str | None = None,
    suspicious_only: bool = False,
) -> list[dict[str, Any]]:
    results = incidents[:]

    if min_risk_score is not None:
        results = [i for i in results if i.get("max_risk_score", 0) >= min_risk_score]

    if host:
        host_lower = host.lower()
        results = [
            i for i in results
            if any(host_lower in str(h).lower() for h in i.get("hosts", []))
        ]

    if technique:
        tech_lower = technique.lower()
        results = [
            i for i in results
            if any(
                tech_lower in str(match.get("technique", "")).lower()
                or tech_lower in str(match.get("name", "")).lower()
                or tech_lower in str(match.get("tactic", "")).lower()
                for match in i.get("mitre_techniques", [])
            )
        ]

    if suspicious_only:
        results = [i for i in results if i.get("suspicious_ips")]

    return results
