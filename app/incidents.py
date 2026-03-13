from typing import Any

from app.correlation import build_attack_chains
from app.live_status import load_events
from app.summarizer import summarize_chain


_PRIVATE_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "127.",
)


def build_incidents() -> list[dict[str, Any]]:
    events = load_events()
    chains = build_attack_chains(events)

    incidents: list[dict[str, Any]] = []

    for idx, chain in enumerate(chains, start=1):
        chain_events = chain if isinstance(chain, list) else chain.get("events", [])

        if not chain_events:
            continue

        hosts = sorted({e.get("host") for e in chain_events if e.get("host")})
        users = sorted({e.get("username") for e in chain_events if e.get("username")})
        suspicious_ips = sorted({
            ip
            for e in chain_events
            for ip in [e.get("src_ip"), e.get("dest_ip")]
            if ip and not ip.startswith(_PRIVATE_PREFIXES)
        })

        max_risk_score = max((e.get("risk_score", 0) or 0) for e in chain_events)

        mitre_techniques = []
        seen_techniques = set()
        for event in chain_events:
            for match in event.get("mitre_matches", []) or []:
                technique_key = (
                    match.get("technique"),
                    match.get("name"),
                    match.get("tactic"),
                )
                if technique_key not in seen_techniques:
                    seen_techniques.add(technique_key)
                    mitre_techniques.append(match)

        title_host = hosts[0] if hosts else "unknown-host"

        incident = {
            "incident_id": f"chain-{idx}",
            "title": f"Incident on {title_host}",
            "hosts": hosts,
            "users": users,
            "suspicious_ips": suspicious_ips,
            "event_count": len(chain_events),
            "max_risk_score": max_risk_score,
            "mitre_techniques": mitre_techniques,
            "summary": summarize_chain(chain_events),
            "timeline": chain_events,
        }

        incidents.append(incident)

    incidents.sort(key=lambda x: x.get("max_risk_score", 0), reverse=True)
    return incidents


def get_incident_by_id(incident_id: str) -> dict[str, Any] | None:
    incidents = build_incidents()
    for incident in incidents:
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
    filtered = incidents

    if min_risk_score is not None:
        filtered = [i for i in filtered if i.get("max_risk_score", 0) >= min_risk_score]

    if host:
        host_lower = host.lower()
        filtered = [
            i for i in filtered
            if any(h and host_lower in h.lower() for h in i.get("hosts", []))
        ]

    if technique:
        technique_lower = technique.lower()
        filtered = [
            i for i in filtered
            if any(
                technique_lower in (m.get("technique", "") or "").lower()
                or technique_lower in (m.get("name", "") or "").lower()
                or technique_lower in (m.get("tactic", "") or "").lower()
                for m in i.get("mitre_techniques", [])
            )
        ]

    if suspicious_only:
        filtered = [i for i in filtered if i.get("suspicious_ips")]

    return filtered
