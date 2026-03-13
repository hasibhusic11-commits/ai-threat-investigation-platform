from typing import Any


def summarize_chain_fallback(chain):
    events = chain if isinstance(chain, list) else chain.get("events", [])

    if not events:
        return {
            "summary": "No events in chain",
            "why_suspicious": "No correlated events were available.",
            "likely_progression": "unknown",
            "recommended_actions": [],
            "risk_score": 0,
        }

    first = events[0]
    last = events[-1]

    src = first.get("src_ip", "unknown")
    dst = first.get("dest_ip", "unknown")
    proto = first.get("proto", "unknown")

    event_types = [e.get("event_type", "unknown") for e in events]
    hosts = sorted({e.get("host") for e in events if e.get("host")})
    users = sorted({e.get("username") for e in events if e.get("username")})

    recommendations = [
        "Review the full event timeline.",
        "Validate source and destination IP activity.",
        "Check host and user context for suspicious behavior.",
    ]

    if hosts:
        recommendations.append(f"Investigate host(s): {', '.join(hosts)}.")
    if users:
        recommendations.append(f"Review user account activity for: {', '.join(users)}.")

    return {
        "summary": f"Correlated network activity from {src} to {dst} over {proto}.",
        "why_suspicious": f"The chain contains {len(events)} related event(s) with progression: {' -> '.join(event_types)}.",
        "likely_progression": " -> ".join(event_types),
        "recommended_actions": recommendations,
        "risk_score": min(len(events) * 10, 100),
    }


def summarize_chain(chain):
    return summarize_chain_fallback(chain)
