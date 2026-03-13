import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.cases import (
    add_case_note,
    create_case_from_incident,
    dashboard_case_summary,
    get_case,
    list_cases,
    update_case_owner,
    update_case_priority,
    update_case_status,
)
from app.config import DATA_FILE, SURICATA_EVE_PATH
from app.incidents import build_incidents, filter_incidents, get_incident_by_id
from app.ingest import ingest_logs
from app.live_status import get_live_status, get_recent_events
from app.packet_trace import build_packet_flows, trace_ip
from app.realtime_ingest import process_new_lines
from app.search import search_logs
from app.security import rate_limit, require_api_key
from app.summarizer import summarize_chain

app = FastAPI(title="AI Threat Investigation Platform", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SearchRequest(BaseModel):
    query: str
    limit: int = 5


class CreateCaseRequest(BaseModel):
    incident_id: str
    title: str | None = None
    priority: str = "medium"
    owner: str | None = None


class UpdateCaseStatusRequest(BaseModel):
    status: str


class UpdateCaseOwnerRequest(BaseModel):
    owner: str | None = None


class UpdateCasePriorityRequest(BaseModel):
    priority: str


class AddCaseNoteRequest(BaseModel):
    note: str
    author: str | None = None


def load_raw_logs():
    rows = []
    if not Path(DATA_FILE).exists():
        return rows

    with Path(DATA_FILE).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


@app.get("/")
def root():
    return {"message": "AI Threat Investigation Platform is running"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ai-threat-investigation-platform",
        "version": "6.0.0",
        "suricata_eve_path": str(SURICATA_EVE_PATH),
        "normalized_store_path": str(DATA_FILE),
    }


@app.get("/status/live", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def status_live():
    return get_live_status()


@app.get("/telemetry/recent", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def telemetry_recent(limit: int = Query(20, ge=1, le=100)):
    return {"events": get_recent_events(limit=limit)}


@app.get("/packets/flows", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def packet_flows():
    return {"flows": build_packet_flows()}


@app.get("/packets/trace/{ip}", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def packet_trace(ip: str):
    return {"flows": trace_ip(ip)}


@app.post("/suricata/process", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def process_suricata_now():
    count = process_new_lines()
    return {"status": "success", "processed_count": count}


@app.post("/ingest", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def ingest():
    count = ingest_logs()
    return {"status": "success", "ingested_count": count}


@app.get("/search", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def search(query: str = Query(..., min_length=2, max_length=200), limit: int = Query(5, ge=1, le=20)):
    return {"results": search_logs(query, limit=limit)}


@app.post("/search", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def search_post(request: SearchRequest):
    if len(request.query.strip()) < 2:
        raise HTTPException(status_code=400, detail="Query too short")
    if len(request.query) > 200:
        raise HTTPException(status_code=400, detail="Query too long")
    return {"results": search_logs(request.query, limit=request.limit)}


@app.get("/correlate/summaries", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def correlate_summaries():
    incidents = build_incidents()
    return {
        "results": [
            {
                "incident_id": i["incident_id"],
                "summary": i["summary"],
            }
            for i in incidents
        ]
    }


@app.get("/incidents", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def list_incidents_endpoint(
    min_risk_score: int | None = Query(None, ge=0, le=100),
    host: str | None = Query(None, max_length=100),
    technique: str | None = Query(None, max_length=50),
    suspicious_only: bool = Query(False),
):
    incidents = build_incidents()
    incidents = filter_incidents(
        incidents,
        min_risk_score=min_risk_score,
        host=host,
        technique=technique,
        suspicious_only=suspicious_only,
    )
    return {"incidents": incidents}


@app.get("/incidents/{incident_id}", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def get_incident_endpoint(incident_id: str):
    incident = get_incident_by_id(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident


@app.get("/dashboard/summary", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def dashboard_summary():
    incidents = build_incidents()

    total_incidents = len(incidents)
    high_risk_incidents = len([i for i in incidents if i.get("max_risk_score", 0) >= 50])
    suspicious_ip_incidents = len([i for i in incidents if i.get("suspicious_ips")])

    top_techniques: dict[str, int] = {}
    incidents_by_host: dict[str, int] = {}
    risk_buckets = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for incident in incidents:
        for host in incident.get("hosts", []):
            incidents_by_host[host] = incidents_by_host.get(host, 0) + 1

        risk = incident.get("max_risk_score", 0)
        if risk >= 75:
            risk_buckets["critical"] += 1
        elif risk >= 50:
            risk_buckets["high"] += 1
        elif risk >= 25:
            risk_buckets["medium"] += 1
        else:
            risk_buckets["low"] += 1

        for technique in incident.get("mitre_techniques", []):
            name = technique.get("technique", "UNKNOWN")
            top_techniques[name] = top_techniques.get(name, 0) + 1

    sorted_techniques = sorted(
        [{"technique": k, "count": v} for k, v in top_techniques.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    sorted_hosts = sorted(
        [{"host": k, "count": v} for k, v in incidents_by_host.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    return {
        "total_incidents": total_incidents,
        "high_risk_incidents": high_risk_incidents,
        "suspicious_ip_incidents": suspicious_ip_incidents,
        "top_techniques": sorted_techniques[:8],
        "incidents_by_host": sorted_hosts[:8],
        "risk_distribution": [
            {"name": "Low", "value": risk_buckets["low"]},
            {"name": "Medium", "value": risk_buckets["medium"]},
            {"name": "High", "value": risk_buckets["high"]},
            {"name": "Critical", "value": risk_buckets["critical"]},
        ],
        "case_summary": dashboard_case_summary(),
    }


@app.get("/cases", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def list_cases_endpoint():
    return {"cases": list_cases()}


@app.get("/cases/{case_id}", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def get_case_endpoint(case_id: str):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.post("/cases", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def create_case_endpoint(request: CreateCaseRequest):
    try:
        return create_case_from_incident(
            incident_id=request.incident_id,
            title=request.title,
            priority=request.priority,
            owner=request.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/cases/{case_id}/status", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def update_case_status_endpoint(case_id: str, request: UpdateCaseStatusRequest):
    try:
        return update_case_status(case_id, request.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/cases/{case_id}/owner", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def update_case_owner_endpoint(case_id: str, request: UpdateCaseOwnerRequest):
    try:
        return update_case_owner(case_id, request.owner)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/cases/{case_id}/priority", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def update_case_priority_endpoint(case_id: str, request: UpdateCasePriorityRequest):
    try:
        return update_case_priority(case_id, request.priority)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/cases/{case_id}/notes", dependencies=[Depends(rate_limit), Depends(require_api_key)])
def add_case_note_endpoint(case_id: str, request: AddCaseNoteRequest):
    try:
        return add_case_note(case_id, request.note, request.author)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
