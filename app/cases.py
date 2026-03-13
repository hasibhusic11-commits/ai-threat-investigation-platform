import json
from datetime import datetime, timezone
from typing import Any

from app.config import CASE_STORE_FILE
from app.incidents import get_incident_by_id


VALID_CASE_STATUSES = {"open", "triaged", "closed"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}


def _ensure_store() -> None:
    CASE_STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not CASE_STORE_FILE.exists():
        CASE_STORE_FILE.write_text("[]", encoding="utf-8")


def _load_cases() -> list[dict[str, Any]]:
    _ensure_store()
    try:
        text = CASE_STORE_FILE.read_text(encoding="utf-8").strip()
        if not text:
            return []
        return json.loads(text)
    except Exception:
        return []


def _save_cases(cases: list[dict[str, Any]]) -> None:
    _ensure_store()
    CASE_STORE_FILE.write_text(json.dumps(cases, indent=2), encoding="utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_case_id(cases: list[dict[str, Any]]) -> str:
    if not cases:
        return "case-1"

    max_num = 0
    for case in cases:
        case_id = case.get("case_id", "")
        if case_id.startswith("case-"):
            try:
                max_num = max(max_num, int(case_id.split("-")[1]))
            except Exception:
                pass

    return f"case-{max_num + 1}"


def list_cases() -> list[dict[str, Any]]:
    return _load_cases()


def get_case(case_id: str) -> dict[str, Any] | None:
    for case in _load_cases():
        if case.get("case_id") == case_id:
            return case
    return None


def create_case_from_incident(
    incident_id: str,
    title: str | None = None,
    priority: str = "medium",
    owner: str | None = None,
) -> dict[str, Any]:
    priority = priority.lower()
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Use one of: {sorted(VALID_PRIORITIES)}")

    incident = get_incident_by_id(incident_id)
    if not incident:
        raise ValueError("Incident not found")

    cases = _load_cases()

    new_case = {
        "case_id": _next_case_id(cases),
        "incident_id": incident_id,
        "title": title or incident.get("title") or f"Case for {incident_id}",
        "status": "open",
        "priority": priority,
        "owner": owner,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "notes": [],
        "incident_snapshot": {
            "incident_id": incident.get("incident_id"),
            "title": incident.get("title"),
            "hosts": incident.get("hosts", []),
            "users": incident.get("users", []),
            "max_risk_score": incident.get("max_risk_score", 0),
            "suspicious_ips": incident.get("suspicious_ips", []),
            "event_count": incident.get("event_count", 0),
        },
    }

    cases.append(new_case)
    _save_cases(cases)
    return new_case


def update_case_status(case_id: str, status: str) -> dict[str, Any]:
    status = status.lower()
    if status not in VALID_CASE_STATUSES:
        raise ValueError(f"Invalid status. Use one of: {sorted(VALID_CASE_STATUSES)}")

    cases = _load_cases()
    for case in cases:
        if case.get("case_id") == case_id:
            case["status"] = status
            case["updated_at"] = _now_iso()
            _save_cases(cases)
            return case

    raise ValueError("Case not found")


def update_case_owner(case_id: str, owner: str | None) -> dict[str, Any]:
    cases = _load_cases()
    for case in cases:
        if case.get("case_id") == case_id:
            case["owner"] = owner
            case["updated_at"] = _now_iso()
            _save_cases(cases)
            return case

    raise ValueError("Case not found")


def update_case_priority(case_id: str, priority: str) -> dict[str, Any]:
    priority = priority.lower()
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Use one of: {sorted(VALID_PRIORITIES)}")

    cases = _load_cases()
    for case in cases:
        if case.get("case_id") == case_id:
            case["priority"] = priority
            case["updated_at"] = _now_iso()
            _save_cases(cases)
            return case

    raise ValueError("Case not found")


def add_case_note(case_id: str, note: str, author: str | None = None) -> dict[str, Any]:
    if not note.strip():
        raise ValueError("Note cannot be empty")

    cases = _load_cases()
    for case in cases:
        if case.get("case_id") == case_id:
            case.setdefault("notes", []).append(
                {
                    "author": author,
                    "note": note,
                    "timestamp": _now_iso(),
                }
            )
            case["updated_at"] = _now_iso()
            _save_cases(cases)
            return case

    raise ValueError("Case not found")


def dashboard_case_summary() -> dict[str, Any]:
    cases = _load_cases()

    return {
        "total_cases": len(cases),
        "open_cases": len([c for c in cases if c.get("status") == "open"]),
        "triaged_cases": len([c for c in cases if c.get("status") == "triaged"]),
        "closed_cases": len([c for c in cases if c.get("status") == "closed"]),
        "high_priority_cases": len([c for c in cases if c.get("priority") in {"high", "critical"}]),
    }
