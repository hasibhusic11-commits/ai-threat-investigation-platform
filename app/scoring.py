from typing import Any


KEYWORD_SCORES = [
    ("failed ssh login", 20),
    ("failed authentication", 15),
    ("locked out", 10),
    ("multiple failed ssh login attempts", 25),
    ("repeated failed authentication attempts", 20),
    ("successful admin login", 30),
    ("after previous failures", 25),
    ("after repeated failures", 25),
    ("root", 10),
    ("powershell", 20),
    ("encoded command", 20),
    ("privilege escalation", 30),
    ("administrator account", 25),
    ("admin account created", 25),
    ("service creation", 20),
    ("dns requests", 10),
    ("random-looking domains", 20),
    ("algorithmically generated domains", 25),
    ("outbound connection", 15),
    ("untrusted ip", 20),
    ("rare domain", 20),
    ("unsigned binary", 20),
    ("ssh scan", 15),
    ("port scan", 15),
    ("malware", 30),
    ("trojan", 30),
    ("ransomware", 40),
]


def score_to_severity(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def calculate_risk_score(
    event_text: str,
    mitre_matches: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    text = event_text.lower()
    score = 0
    matched_reasons: list[dict[str, Any]] = []

    safe_mitre_matches = mitre_matches or []

    for keyword, points in KEYWORD_SCORES:
        if keyword in text:
            score += points
            matched_reasons.append({"reason": keyword, "points": points})

    mitre_bonus = min(len(safe_mitre_matches) * 10, 20)
    if mitre_bonus:
        score += mitre_bonus
        matched_reasons.append({"reason": "mitre_match_bonus", "points": mitre_bonus})

    score = min(score, 100)

    return {
        "risk_score": score,
        "calculated_severity": score_to_severity(score),
        "score_reasons": matched_reasons,
    }
