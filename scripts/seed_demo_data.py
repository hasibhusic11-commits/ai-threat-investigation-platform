import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.config import CASE_STORE_FILE, DATA_FILE

random.seed(42)

HOSTS = [
    "wkstn-07",
    "finance-pc-02",
    "eng-laptop-14",
    "dc-01",
    "web-01",
    "mail-01",
    "db-02",
    "vpn-gateway",
    "hr-laptop-03",
    "ws-44",
    "server-1",
    "server-2",
]

USERS = [
    "jsmith",
    "adoe",
    "temp_admin",
    "svc_backup",
    "analyst1",
    "finance.user",
    "hr.manager",
    "it.support",
    "root",
    "administrator",
]

SCENARIOS = [
    {
        "name": "Phishing to Credential Abuse",
        "events": [
            {"event_type": "dns", "risk_score": 20, "domain": "microsoft-login-alerts.com"},
            {"event_type": "authentication", "risk_score": 45, "action": "login_failure"},
            {"event_type": "authentication", "risk_score": 60, "action": "login_success"},
            {"event_type": "process", "risk_score": 65, "process_name": "powershell.exe"},
        ],
        "priority": "high",
        "status": "investigating",
    },
    {
        "name": "DNS Beaconing / C2",
        "events": [
            {"event_type": "dns", "risk_score": 30, "domain": "cdn-update-check.net"},
            {"event_type": "flow", "risk_score": 40},
            {"event_type": "dns", "risk_score": 45, "domain": "dropbox-cdn-sync.net"},
            {"event_type": "flow", "risk_score": 55},
        ],
        "priority": "high",
        "status": "open",
    },
    {
        "name": "Brute Force on Admin Account",
        "events": [
            {"event_type": "authentication", "risk_score": 25, "action": "login_failure"},
            {"event_type": "authentication", "risk_score": 30, "action": "login_failure"},
            {"event_type": "authentication", "risk_score": 35, "action": "login_failure"},
            {"event_type": "authentication", "risk_score": 60, "action": "login_success"},
        ],
        "priority": "critical",
        "status": "triaged",
    },
    {
        "name": "Suspicious PowerShell Execution",
        "events": [
            {"event_type": "process", "risk_score": 35, "process_name": "powershell.exe"},
            {"event_type": "flow", "risk_score": 40},
            {"event_type": "process", "risk_score": 50, "process_name": "cmd.exe"},
        ],
        "priority": "medium",
        "status": "open",
    },
    {
        "name": "Lateral Movement via Remote Services",
        "events": [
            {"event_type": "authentication", "risk_score": 30, "action": "login_success"},
            {"event_type": "flow", "risk_score": 50},
            {"event_type": "flow", "risk_score": 65},
            {"event_type": "process", "risk_score": 70, "process_name": "wmic.exe"},
        ],
        "priority": "critical",
        "status": "contained",
    },
    {
        "name": "Exfiltration over HTTPS",
        "events": [
            {"event_type": "process", "risk_score": 30, "process_name": "python.exe"},
            {"event_type": "flow", "risk_score": 55},
            {"event_type": "flow", "risk_score": 70},
            {"event_type": "flow", "risk_score": 80},
        ],
        "priority": "critical",
        "status": "investigating",
    },
]

MITRE_MAP = {
    "dns": {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "authentication": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "process": {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "flow": {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}

PRIVATE_IPS = [
    "10.0.5.12",
    "10.0.5.18",
    "10.0.8.44",
    "10.0.10.7",
    "10.0.10.21",
    "10.0.12.9",
    "192.168.1.25",
    "192.168.1.50",
    "192.168.1.77",
]

PUBLIC_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "45.33.32.156",
    "91.240.118.172",
    "185.220.101.17",
    "203.0.113.10",
    "198.51.100.24",
    "104.21.44.12",
]

OWNERS = ["Hasib", "SOC Tier 1", "SOC Tier 2", "IR Lead", "Detection Engineer"]

NOTES = [
    "Initial triage completed. Escalating for deeper review.",
    "Suspicious connection overlaps with unusual login pattern.",
    "Recommend checking EDR process tree and DNS history.",
    "User claims no knowledge of recent login activity.",
    "Potential false positive, but requires containment validation.",
    "Correlated with prior detections on the same host.",
    "Need to validate whether source IP belongs to known vendor infrastructure.",
]


def iso_now_minus(minutes_ago: int) -> str:
    ts = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return ts.isoformat().replace("+00:00", "Z")


def build_event(event_id: int, scenario_name: str, event_template: dict, host: str, user: str) -> dict:
    src_ip = random.choice(PRIVATE_IPS)
    dest_ip = random.choice(PUBLIC_IPS)
    event_type = event_template["event_type"]

    event = {
        "id": event_id,
        "timestamp": iso_now_minus(random.randint(1, 4000)),
        "event_type": event_type,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": random.randint(1024, 65000),
        "dest_port": random.choice([53, 80, 443, 22, 3389, 8080]),
        "proto": random.choice(["TCP", "UDP"]),
        "host": host,
        "username": user,
        "risk_score": event_template["risk_score"],
        "scenario": scenario_name,
        "mitre_matches": [MITRE_MAP[event_type]],
    }

    if event_type == "dns":
        event["dns"] = {"rrname": event_template["domain"]}
        event["dest_port"] = 53
        event["proto"] = "UDP"

    if event_type == "authentication":
        event["action"] = event_template["action"]

    if event_type == "process":
        event["process_name"] = event_template["process_name"]

    if event_type == "flow":
        event["dest_port"] = random.choice([80, 443, 8080, 8443])

    return event


def main():
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    CASE_STORE_FILE.parent.mkdir(parents=True, exist_ok=True)

    DATA_FILE.write_text("", encoding="utf-8")

    all_events = []
    cases = []
    event_id = 1
    case_id = 1

    for scenario in SCENARIOS:
        for _ in range(4):
            host = random.choice(HOSTS)
            user = random.choice(USERS)
            incident_chain = []

            for event_template in scenario["events"]:
                event = build_event(event_id, scenario["name"], event_template, host, user)
                all_events.append(event)
                incident_chain.append(event)
                event_id += 1

            notes = []
            for idx in range(random.randint(1, 3)):
                notes.append(
                    {
                        "note_id": f"note-{case_id}-{idx + 1}",
                        "author": random.choice(OWNERS),
                        "note": random.choice(NOTES),
                        "created_at": iso_now_minus(random.randint(1, 2000)),
                    }
                )

            cases.append(
                {
                    "case_id": f"case-{case_id}",
                    "incident_id": f"chain-{case_id}",
                    "title": scenario["name"],
                    "status": scenario["status"],
                    "priority": scenario["priority"],
                    "owner": random.choice(OWNERS),
                    "created_at": iso_now_minus(random.randint(100, 5000)),
                    "updated_at": iso_now_minus(random.randint(1, 90)),
                    "notes": notes,
                }
            )
            case_id += 1

    with DATA_FILE.open("a", encoding="utf-8") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    CASE_STORE_FILE.write_text(json.dumps(cases, indent=2), encoding="utf-8")

    print(f"Seeded {len(all_events)} events")
    print(f"Seeded {len(cases)} cases")


if __name__ == "__main__":
    main()
