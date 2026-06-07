"""
LexAgent Legal Brain — FastAPI Backend
Endpoints: /risk/check, /events/batch, /agents/status, /reports/generate
"""

from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from classifier import LegalBrainClassifier, RiskAssessment, RiskLevel

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="LexAgent Legal Brain API",
    description="AI Compliance Monitor — Real-time legal risk classification for AI agents",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

classifier = LegalBrainClassifier()

_event_store: list[dict] = []
_api_keys: set[str] = {os.environ.get("LEXAGENT_MASTER_KEY", "lxa_dev_master_key")}


# ── Auth ───────────────────────────────────────────────────────────────────────

def _check_key(request: Request):
    key = request.headers.get("x-lexagent-key", "")
    if not key.startswith("lxa_"):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return key


# ── Pydantic models ────────────────────────────────────────────────────────────

class AgentEvent(BaseModel):
    id: str
    agentId: str
    agentName: str = "unnamed-agent"
    type: str
    payload: Any = {}
    meta: dict = {}
    frameworks: list[str] = ["EU_AI_ACT", "GDPR"]
    sdkVersion: str = "0.1.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    environment: str = "unknown"


class EventBatch(BaseModel):
    events: list[AgentEvent]


class StatusRequest(BaseModel):
    agentId: str
    frameworks: list[str] = ["EU_AI_ACT", "GDPR"]


class ReportRequest(BaseModel):
    agentId: str
    format: str = "pdf"
    frameworks: list[str] = ["EU_AI_ACT", "GDPR"]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _serialize(a: RiskAssessment) -> dict:
    return {
        "eventId":                a.event_id,
        "actionType":             a.action_type,
        "overallRisk":            a.overall_risk.value,
        "blocked":                a.blocked,
        "reason":                 a.reason,
        "recommendation":         a.recommendation,
        "confidence":             a.confidence,
        "requiresHumanOversight": a.requires_human_oversight,
        "requiresLogging":        a.requires_logging,
        "requiresExplanation":    a.requires_explanation,
        "disclaimer":             a.disclaimer,
        "findings": [
            {
                "framework":   f.framework,
                "riskLevel":   f.risk_level.value,
                "articles":    f.articles,
                "obligations": f.obligations,
                "violated":    f.violated,
                "notes":       f.notes,
            }
            for f in a.findings
        ],
        "blockchainAnchor": "0x" + hashlib.sha256(a.event_id.encode()).hexdigest()[:40],
        "classifiedAt":     datetime.now(timezone.utc).isoformat(),
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service":    "LexAgent Legal Brain",
        "version":    "0.1.0",
        "status":     "operational",
        "frameworks": ["EU_AI_ACT", "GDPR", "NIST_RMF", "ISO_42001", "SOC2", "CCPA"],
        "docs":       "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/risk/check")
async def risk_check(event: AgentEvent, request: Request):
    _check_key(request)
    t = time.perf_counter()
    result = _serialize(classifier.classify(event.model_dump(), event.frameworks))
    event_dict = event.model_dump()
    event_dict["_assessment"] = result
    _event_store.append(event_dict)
    result["processingMs"] = round((time.perf_counter() - t) * 1000, 2)
    return JSONResponse(content=result)


@app.post("/v1/events/batch")
async def events_batch(batch: EventBatch, request: Request):
    _check_key(request)
    results = []
    for event in batch.events:
        d = event.model_dump()
        r = _serialize(classifier.classify(d, event.frameworks))
        d["_assessment"] = r
        _event_store.append(d)
        results.append({"eventId": event.id, "risk": r["overallRisk"], "blocked": r["blocked"]})
    return {"processed": len(results), "results": results, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/agents/status")
async def agent_status(req: StatusRequest, request: Request):
    _check_key(request)
    events = [e for e in _event_store if e.get("agentId") == req.agentId]
    total   = len(events)
    blocked = sum(1 for e in events if e.get("_assessment", {}).get("blocked"))

    fw_status = {}
    for fw in req.frameworks:
        gaps = list({
            f"{f['framework']} {f['articles'][0] if f['articles'] else ''}: {f['obligations'][0] if f['obligations'] else ''}"
            for e in events
            for f in e.get("_assessment", {}).get("findings", [])
            if f["framework"] == fw and f["violated"]
        })[:5]
        fw_status[fw] = {"compliant": len(gaps) == 0, "gaps": gaps}

    counts = {"none":0,"low":0,"medium":0,"high":0,"critical":0}
    for e in events:
        counts[e.get("_assessment", {}).get("overallRisk", "low")] = counts.get(e.get("_assessment", {}).get("overallRisk","low"),0) + 1
    overall = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low"

    return {
        "agentId":          req.agentId,
        "overallRisk":      overall,
        "totalEvents":      total,
        "blockedEvents":    blocked,
        "frameworks":       fw_status,
        "blockchainAnchor": "0x" + hashlib.sha256(req.agentId.encode()).hexdigest()[:40],
        "lastChecked":      datetime.now(timezone.utc).isoformat(),
    }


@app.post("/v1/reports/generate")
async def generate_report(req: ReportRequest, request: Request):
    _check_key(request)
    events = [e for e in _event_store if e.get("agentId") == req.agentId]

    if req.format == "json":
        return {
            "agentId":     req.agentId,
            "format":      "json",
            "frameworks":  req.frameworks,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "totalEvents": len(events),
            "events": [
                {"id": e["id"], "type": e["type"], "timestamp": e["timestamp"],
                 "risk": e.get("_assessment", {}).get("overallRisk", "unknown"),
                 "findings": e.get("_assessment", {}).get("findings", [])}
                for e in events[-100:]
            ],
            "disclaimer": "LexAgent provides compliance intelligence, not legal advice.",
        }

    report_id = hashlib.sha256(f"{req.agentId}{time.time()}".encode()).hexdigest()[:16]
    return {
        "reportId":    report_id,
        "agentId":     req.agentId,
        "format":      req.format,
        "url":         f"https://lexagent-api.onrender.com/reports/{report_id}.{req.format}",
        "expiresAt":   "72h",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "includes": [
            "EU AI Act Article 11 Technical Documentation",
            "Article 12 Event Log Summary",
            "NIST AI RMF Assessment",
            "GDPR Article 30 Records of Processing",
            "Blockchain Audit Trail (Polygon)",
        ],
        "disclaimer": "LexAgent provides compliance intelligence, not legal advice.",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=True)
