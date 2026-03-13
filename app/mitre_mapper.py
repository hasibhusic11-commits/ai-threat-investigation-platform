from typing import Any


MITRE_RULES = [
    {
        "keywords": ["ssh scan", "port scan", "suspicious ssh scan", "network scan"],
        "technique": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Reconnaissance",
    },
    {
        "keywords": ["failed ssh login", "failed authentication", "brute force", "login attempts", "locked out"],
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["powershell", "encoded command"],
        "technique": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
    },
    {
        "keywords": ["privilege escalation", "admin account created", "administrator account", "service creation"],
        "technique": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    {
        "keywords": ["dns requests", "random-looking domains", "rare domain", "dns tunneling"],
        "technique": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
    {
        "keywords": ["outbound connection", "untrusted ip", "exfiltration", "unsigned binary", "data transfer"],
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
]


def map_mitre(event_text: str) -> list[dict[str, Any]]:
    if not event_text:
        return []

    text = event_text.lower()
    matches: list[dict[str, Any]] = []

    for rule in MITRE_RULES:
        if any(keyword in text for keyword in rule["keywords"]):
            matches.append(
                {
                    "technique": rule["technique"],
                    "name": rule["name"],
                    "tactic": rule["tactic"],
                }
            )

    return matches
