import json
from typing import Any


def build_chain_prompt(chain: dict[str, Any]) -> str:
    events_text = []
    for event in chain.get("events", []):
        events_text.append(
            f"- [{event.get('timestamp')}] "
            f"type={event.get('event_type')} "
            f"severity={event.get('severity')} "
            f"host={event.get('host')} "
            f"user={event.get('username')} "
            f"text={event.get('event_text')}"
        )

    return f"""
You are a cybersecurity incident analyst.

Given the attack chain below, write a concise incident summary in plain professional language.

Requirements:
- State what likely happened
- Explain why it is suspicious
- Mention likely attack progression
- Mention any relevant host/user/IP context
- Give 3 recommended next steps
- Keep the output structured as JSON with keys:
  summary, why_suspicious, likely_progression, recommended_actions

Attack chain metadata:
chain_id: {chain.get("chain_id")}
hosts: {chain.get("hosts")}
usernames: {chain.get("usernames")}
event_count: {chain.get("event_count")}

Events:
{chr(10).join(events_text)}
""".strip()


def summarize_chain_fallback(chain: dict[str, Any]) -> dict[str, Any]:
    events = chain.get("events", [])
    hosts = ", ".join(chain.get("hosts", [])) or "unknown hosts"
    users = ", ".join(chain.get("usernames", [])) or "unknown users"

    event_types = [e.get("event_type", "unknown") for e in events]
    progression = " -> ".join(event_types)

    summary = (
        f"Potential multi-stage security incident detected involving {hosts} "
        f"and user(s) {users}. The observed events suggest a related attack sequence."
    )

    why_suspicious = (
        f"The chain contains {len(events)} related events with a progression of {progression}, "
        f"indicating more than an isolated alert and suggesting coordinated malicious behavior."
    )

    recommended_actions = [
        f"Isolate or closely monitor affected host(s): {hosts}.",
        "Review authentication history, process execution, and outbound connections for the impacted assets.",
        "Validate account activity, reset credentials if needed, and investigate persistence or exfiltration indicators.",
    ]

    return {
        "summary": summary,
        "why_suspicious": why_suspicious,
        "likely_progression": progression,
        "recommended_actions": recommended_actions,
    }


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
