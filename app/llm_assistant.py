import json
from typing import Any

import requests

from app.config import LLM_MODE, OLLAMA_BASE_URL, OLLAMA_MODEL


def _safe_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _max_risk_label(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _build_prompt(incident: dict[str, Any]) -> str:
    return f"""
You are a senior SOC analyst writing concise incident investigation notes.

Return valid JSON only with exactly these keys:
- executive_summary
- analyst_notes
- likely_attack_stage
- confidence
- affected_assets
- affected_users
- suspicious_indicators
- top_risks
- recommended_actions
- containment_steps

Rules:
- analyst_notes must be 4 to 7 bullet-style strings
- recommended_actions must be 3 to 6 bullet-style strings
- containment_steps must be 2 to 5 bullet-style strings
- confidence must be an integer from 0 to 100
- keep language direct, professional, and SOC-focused
- do not include markdown fences

Incident:
{json.dumps(incident, indent=2)}
""".strip()


def _build_fallback_notes(incident: dict[str, Any]) -> dict[str, Any]:
    title = incident.get("title", "Unknown Incident")
    incident_id = incident.get("incident_id", "unknown")
    risk = int(incident.get("max_risk_score", 0))
    risk_label = _max_risk_label(risk)

    hosts = _safe_list(incident.get("hosts"))
    users = _safe_list(incident.get("users"))
    suspicious_ips = _safe_list(incident.get("suspicious_ips"))
    techniques = incident.get("mitre_techniques", []) or []
    event_count = int(incident.get("event_count", 0))

    technique_names = []
    for t in techniques:
        if isinstance(t, dict):
            name = t.get("name") or t.get("technique")
            if name:
                technique_names.append(str(name))

    technique_names = sorted(set(technique_names))

    stage = "Suspicious Activity"
    if risk >= 75:
        stage = "Active Compromise Likely"
    elif risk >= 50:
        stage = "Malicious Activity Likely"
    elif risk >= 25:
        stage = "Investigation Required"

    executive_summary = (
        f"{title} ({incident_id}) is currently assessed as {risk_label.lower()} severity "
        f"based on {event_count} correlated event(s). "
        f"The activity involves {len(hosts)} host(s), {len(users)} user account(s), "
        f"and {len(suspicious_ips)} suspicious indicator(s)."
    )

    analyst_notes = [
        f"Incident {incident_id} was correlated from {event_count} related security events.",
        f"Current severity is {risk_label} with a maximum observed risk score of {risk}.",
        f"Affected hosts: {', '.join(hosts) if hosts else 'none identified'}.",
        f"Affected users: {', '.join(users) if users else 'none identified'}.",
        f"Suspicious indicators: {', '.join(suspicious_ips) if suspicious_ips else 'none identified'}.",
        f"Observed ATT&CK-aligned behaviors: {', '.join(technique_names) if technique_names else 'no mapped techniques available'}.",
    ]

    top_risks = [
        "Potential malicious external communication" if suspicious_ips else "Host-level suspicious activity requires validation",
        "Possible credential misuse" if users else "No confirmed user abuse yet",
        "Lateral or follow-on activity cannot be ruled out until timeline review is completed",
    ]

    recommended_actions = [
        "Review the correlated timeline to identify the initial trigger and follow-on activity.",
        "Validate the affected host activity in EDR, authentication, and DNS/network telemetry.",
        "Check suspicious IPs and domains against internal and external threat intelligence sources.",
        "Confirm whether the observed behavior matches expected administrative or business activity.",
    ]

    containment_steps = [
        "Isolate the affected host if malicious execution or beaconing is confirmed.",
        "Reset impacted credentials if unauthorized authentication activity is suspected.",
        "Block confirmed malicious IPs/domains at network and endpoint control points.",
    ]

    return {
        "executive_summary": executive_summary,
        "analyst_notes": analyst_notes,
        "likely_attack_stage": stage,
        "confidence": min(max(risk, 15), 95),
        "affected_assets": hosts,
        "affected_users": users,
        "suspicious_indicators": suspicious_ips,
        "top_risks": top_risks,
        "recommended_actions": recommended_actions,
        "containment_steps": containment_steps,
        "llm_mode": "fallback",
    }


def _run_ollama(incident: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": _build_prompt(incident),
            "stream": False,
            "format": "json",
        },
        timeout=90,
    )
    response.raise_for_status()

    body = response.json()
    text = body.get("response", "{}").strip()
    parsed = json.loads(text)

    parsed["llm_mode"] = "ollama"
    return parsed


def explain_incident_with_llm(incident: dict[str, Any]) -> dict[str, Any]:
    if not incident:
        return {
            "executive_summary": "Incident not found.",
            "analyst_notes": ["No incident data was available for analysis."],
            "likely_attack_stage": "Unknown",
            "confidence": 0,
            "affected_assets": [],
            "affected_users": [],
            "suspicious_indicators": [],
            "top_risks": [],
            "recommended_actions": [],
            "containment_steps": [],
            "llm_mode": "fallback",
        }

    if LLM_MODE == "ollama":
        try:
            return _run_ollama(incident)
        except Exception as exc:
            result = _build_fallback_notes(incident)
            result["llm_error"] = str(exc)
            return result

    return _build_fallback_notes(incident)
