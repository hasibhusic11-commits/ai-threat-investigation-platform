import json
from typing import Any


def summarize_chain_fallback(chain: dict[str, Any]) -> dict[str, Any]:
    events = chain.get("events", [])
    hosts = ", ".join(chain.get("hosts", [])) or "unknown hosts"
    users = ", ".join(chain.get("usernames", [])) or "unknown users"

    event_types = [e.get("event_type", "unknown") for e in events]
    progression = " -> ".join(event_types)

    highest_risk = 0
    for event in events:
        risk_score = event.get("risk_score", 0)
        if isinstance(risk_score, (int, float)) and risk_score > highest_risk:
            highest_risk = risk_score

    summary = (
        f"Potential multi-stage security incident detected involving host(s) {hosts} "
        f"and user(s) {users}. The event chain suggests a related sequence of suspicious activity."
    )

    why_suspicious = (
        f"The observed progression ({progression}) and a maximum risk score of {highest_risk} "
        f"indicate that these events are likely related rather than isolated."
    )

    recommended_actions = [
        f"Contain or closely monitor affected host(s): {hosts}.",
        "Review authentication, process execution, and outbound network activity for the involved assets.",
        "Validate account activity, reset credentials if necessary, and investigate persistence or exfiltration indicators.",
    ]

    return {
        "summary": summary,
        "why_suspicious": why_suspicious,
        "likely_progression": progression,
        "recommended_actions": recommended_actions,
    }


def build_chain_prompt(chain: dict[str, Any]) -> str:
    event_lines = []
    for event in chain.get("events", []):
        event_lines.append(
            f"- timestamp={event.get('timestamp')} "
            f"type={event.get('event_type')} "
            f"severity={event.get('final_severity', event.get('severity'))} "
            f"risk_score={event.get('risk_score')} "
            f"host={event.get('host')} "
            f"user={event.get('username')} "
            f"src_ip={event.get('src_ip')} "
            f"dest_ip={event.get('dest_ip')} "
            f"text={event.get('event_text')}"
        )

    return f"""
You are a cybersecurity incident analyst.

Analyze the following correlated attack chain and return STRICT JSON with these keys:
summary
why_suspicious
likely_progression
recommended_actions

Requirements:
- summary: 2-4 sentences
- why_suspicious: 2-4 sentences
- likely_progression: concise string
- recommended_actions: array of exactly 3 action items

Chain metadata:
chain_id: {chain.get("chain_id")}
hosts: {chain.get("hosts")}
usernames: {chain.get("usernames")}
event_count: {chain.get("event_count")}

Events:
{chr(10).join(event_lines)}
""".strip()


def try_openai_summary(chain: dict[str, Any]) -> dict[str, Any] | None:
    try:
        from openai import OpenAI
    except ImportError:
        return None

    try:
        client = OpenAI()
        prompt = build_chain_prompt(chain)

        response = client.responses.create(
            model="gpt-4.1-mini",
            input=prompt,
        )

        text = response.output_text.strip()
        return json.loads(text)
    except Exception:
        return None


def summarize_chain(chain: dict[str, Any]) -> dict[str, Any]:
    llm_result = try_openai_summary(chain)
    if llm_result:
        return llm_result
    return summarize_chain_fallback(chain)
