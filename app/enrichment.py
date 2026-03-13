import re
from typing import Any

from app.mitre_mapper import map_mitre
from app.scoring import calculate_risk_score
from app.threat_intel import check_ip_reputation


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 1) >= SEVERITY_ORDER.get(b, 1) else b


def extract_indicators(text: str) -> dict[str, list[str]]:
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    host_matches = re.findall(
        r"\b(?:server|host|ws|workstation|pc|laptop|sensor|firewall)[-_]?[a-zA-Z0-9]*\b",
        text,
        flags=re.IGNORECASE,
    )

    return {
        "ips": list(set(ip_matches)),
        "hosts": list(set(host_matches)),
    }


def enrich_event(event_text: str, existing_severity: str | None = None) -> dict[str, Any]:
    final_severity = existing_severity.lower() if existing_severity else "low"

    indicators = extract_indicators(event_text or "")
    mitre_matches = map_mitre(event_text or "") or []
    scoring = calculate_risk_score(event_text or "", mitre_matches)

    threat_intel = None
    if indicators["ips"]:
        threat_intel = check_ip_reputation(indicators["ips"][0])

    final_severity = max_severity(final_severity, scoring["calculated_severity"])

    return {
        "final_severity": final_severity,
        "mitre_matches": mitre_matches,
        "indicators": indicators,
        "rule_match_count": len(mitre_matches),
        "risk_score": scoring["risk_score"],
        "score_reasons": scoring["score_reasons"],
        "threat_intel": threat_intel,
    }
