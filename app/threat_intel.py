import json
import random
import urllib.parse
import urllib.request
from typing import Any

from app.config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL, THREAT_INTEL_MODE


SUSPICIOUS_RANGES = [
    "203.0.113",
    "198.51.100",
    "192.0.2",
]


def _simulated_check(ip: str) -> dict[str, Any]:
    for prefix in SUSPICIOUS_RANGES:
        if ip.startswith(prefix):
            return {
                "source": "simulated",
                "reputation": "suspicious",
                "confidence": random.randint(60, 95),
                "category": "known scanning infrastructure",
            }

    return {
        "source": "simulated",
        "reputation": "unknown",
        "confidence": random.randint(10, 40),
        "category": "no intelligence",
    }


def _abuseipdb_check(ip: str) -> dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {
            "source": "abuseipdb",
            "reputation": "unknown",
            "confidence": 0,
            "category": "missing_api_key",
        }

    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    url = f"{ABUSEIPDB_BASE_URL}?{query}"

    request = urllib.request.Request(
        url,
        headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))

        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))

        if score >= 75:
            reputation = "malicious"
        elif score >= 40:
            reputation = "suspicious"
        else:
            reputation = "unknown"

        return {
            "source": "abuseipdb",
            "reputation": reputation,
            "confidence": score,
            "category": "abuse_confidence_score",
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
        }
    except Exception as exc:
        return {
            "source": "abuseipdb",
            "reputation": "unknown",
            "confidence": 0,
            "category": f"lookup_failed: {exc}",
        }


def check_ip_reputation(ip: str) -> dict[str, Any]:
    if THREAT_INTEL_MODE.lower() == "abuseipdb":
        return _abuseipdb_check(ip)

    return _simulated_check(ip)
