"""
LexAgent Legal Brain — FastAPI Backend
Endpoints: /risk/check, /events/batch, /agents/status, /reports/generate
"""

from __future__ import annotations
import os
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
    description="AI Compliance Counsel — Real-time legal risk classification for AI agents",
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

# In-memory store (replace with Neon DB in production)
_event_store: list[dict] = []
_api_keys: set[str] = {os.environ.get("LEXAGENT_MASTER_KEY", "lxa_dev_master_key")}


# ── Auth ───────────────────────────────────────────────────────────────────────

def verify_key(x_lexagent_key: Optional[str] = Header(None)) -> str:
    if not x_lexagent_key:
        raise HTTPException(status_code=401, detail="Missing X-LexAgent-Key header")
    # In production: validate against DB, check subscription tier
    if not x_lexagent_key.startswith("lxa_"):
        raise HTTPException(status_code=401, detail="Invalid API key format")
    return x_lexagent_key


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


# ── Serialization helper ───────────────────────────────────────────────────────

def _serialize_assessment(a: RiskAssessment) -> dict:
    return {
        "eventId":               a.event_id,
        "actionType":            a.action_type,
        "overallRisk":           a.overall_risk.value,
        "blocked":               a.blocked,
        "reason":                a.reason,
        "recommendation":        a.recommendation,
        "confidence":            a.confidence,
        "requiresHumanOversight": a.requires_human_oversight,
        "requiresLogging":       a.requires_logging,
        "requiresExplanation":   a.requires_explanation,
        "disclaimer":            a.disclaimer,
        "findings": [
            {
                "framework":    f.framework,
                "riskLevel":    f.risk_level.value,
                "articles":     f.articles,
                "obligations":  f.obligations,
                "violated":     f.violated,
                "notes":        f.notes,
            }
            for f in a.findings
        ],
        "blockchainAnchor": _mock_blockchain_anchor(a.event_id),
        "classifiedAt": datetime.now(timezone.utc).isoformat(),
    }


def _mock_blockchain_anchor(event_id: str) -> str:
    """Deterministic mock anchor — replace with real Polygon call in production."""
    h = hashlib.sha256(event_id.encode()).hexdigest()
    return f"0x{h[:40]}"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "LexAgent Legal Brain",
        "version": "0.1.0",
        "status":  "operational",
        "frameworks": ["EU_AI_ACT", "GDPR", "NIST_RMF", "ISO_42001", "SOC2", "CCPA"],
        "enforcement_deadline": "EU AI Act full enforcement: August 2, 2026",
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/risk/check")
async def risk_check(event: AgentEvent, request: Request):
    """
    Synchronous risk classification for HIGH-RISK agent actions.
    Called by SDK before DECISION, DATA_ACCESS, EXTERNAL_WRITE.
    Returns within ~50ms.
    """
    key = request.headers.get("x-lexagent-key", "")
    if not key.startswith("lxa_"):
        raise HTTPException(status_code=401, detail="Invalid API key")

    t_start = time.perf_counter()

    event_dict = event.model_dump()
    assessment = classifier.classify(event_dict, event.frameworks)
    result = _serialize_assessment(assessment)

    # Store event with assessment
    event_dict["_assessment"] = result
    event_dict["_processed_at"] = datetime.now(timezone.utc).isoformat()
    _event_store.append(event_dict)

    result["processingMs"] = round((time.perf_counter() - t_start) * 1000, 2)

    return JSONResponse(content=result)


@app.post("/v1/events/batch")
async def events_batch(batch: EventBatch, request: Request):
    """
    Async batch ingestion for MEDIUM/LOW risk events.
    Classify and store all events. Returns summary.
    """
    key = request.headers.get("x-lexagent-key", "")
    if not key.startswith("lxa_"):
        raise HTTPException(status_code=401, detail="Invalid API key")

    results = []
    for event in batch.events:
        event_dict = event.model_dump()
        assessment = classifier.classify(event_dict, event.frameworks)
        serialized = _serialize_assessment(assessment)
        event_dict["_assessment"] = serialized
        event_dict["_processed_at"] = datetime.now(timezone.utc).isoformat()
        _event_store.append(event_dict)
        results.append({
            "eventId":    event.id,
            "risk":       serialized["overallRisk"],
            "blocked":    serialized["blocked"],
        })

    return {
        "processed": len(results),
        "results":   results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/v1/agents/status")
async def agent_status(req: StatusRequest, request: Request):
    """
    Returns compliance posture of an agent across all configured frameworks.
    """
    key = request.headers.get("x-lexagent-key", "")
    if not key.startswith("lxa_"):
        raise HTTPException(status_code=401, detail="Invalid API key")

    agent_events = [e for e in _event_store if e.get("agentId") == req.agentId]

    total = len(agent_events)
    blocked = sum(1 for e in agent_events if e.get("_assessment", {}).get("blocked"))

    # Aggregate per-framework compliance
    framework_status = {}
    for fw in req.frameworks:
        fw_findings = []
        for e in agent_events:
            assessment = e.get("_assessment", {})
            for finding in assessment.get("findings", []):
                if finding["framework"] == fw and finding["violated"]:
                    fw_findings.append(finding)

        # Identify gaps: unique obligations violated
        gaps = list({
            f"{f['framework']} {f['articles'][0] if f['articles'] else ''}: {f['obligations'][0] if f['obligations'] else ''}"
            for f in fw_findings
        })[:5]

        framework_status[fw] = {
            "compliant": len(gaps) == 0,
            "gaps":      gaps,
            "findings":  len(fw_findings),
        }

    # Overall risk = worst finding across all agent events
    risk_counts = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for e in agent_events:
        r = e.get("_assessment", {}).get("overallRisk", "low")
        risk_counts[r] = risk_counts.get(r, 0) + 1

    if risk_counts["critical"] > 0:
        overall = "critical"
    elif risk_counts["high"] > 0:
        overall = "high"
    elif risk_counts["medium"] > 0:
        overall = "medium"
    else:
        overall = "low"

    return {
        "agentId":          req.agentId,
        "overallRisk":      overall,
        "totalEvents":      total,
        "blockedEvents":    blocked,
        "frameworks":       framework_status,
        "blockchainAnchor": _mock_blockchain_anchor(req.agentId),
        "lastChecked":      datetime.now(timezone.utc).isoformat(),
    }


@app.post("/v1/reports/generate")
async def generate_report(req: ReportRequest, request: Request):
    """
    Generates a regulator-ready compliance report.
    Formats: pdf | json | html
    """
    key = request.headers.get("x-lexagent-key", "")
    if not key.startswith("lxa_"):
        raise HTTPException(status_code=401, detail="Invalid API key")

    agent_events = [e for e in _event_store if e.get("agentId") == req.agentId]

    if req.format == "json":
        # Return full JSON report directly
        return {
            "agentId":    req.agentId,
            "format":     "json",
            "frameworks": req.frameworks,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "totalEvents": len(agent_events),
            "events":     [
                {
                    "id":        e["id"],
                    "type":      e["type"],
                    "timestamp": e["timestamp"],
                    "risk":      e.get("_assessment", {}).get("overallRisk", "unknown"),
                    "findings":  e.get("_assessment", {}).get("findings", []),
                }
                for e in agent_events[-100:]  # last 100 events
            ],
            "disclaimer": (
                "LexAgent provides compliance intelligence, not legal advice. "
                "Consult a qualified attorney for jurisdiction-specific legal opinions."
            ),
        }

    # For PDF/HTML: return a report URL (in production: generate and store PDF)
    report_id = hashlib.sha256(f"{req.agentId}{time.time()}".encode()).hexdigest()[:16]
    return {
        "reportId":   report_id,
        "agentId":    req.agentId,
        "format":     req.format,
        "url":        f"https://api.lexagent.io/reports/{report_id}.{req.format}",
        "expiresAt":  "72h",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "includes": [
            "EU AI Act Article 11 Technical Documentation",
            "Article 12 Event Log Summary",
            "NIST AI RMF Assessment",
            "GDPR Records of Processing (Article 30)",
            "Blockchain Audit Trail (Polygon)",
            "Gap Analysis and Recommendations",
        ],
        "disclaimer": (
            "LexAgent provides compliance intelligence, not legal advice."
        ),
    }


# ── Dev server ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
