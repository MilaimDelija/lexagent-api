"""
LexAgent Compliance Engine — Risk Classifier
Classifies AI agent actions against global legal frameworks.

Frameworks v0.1: EU AI Act, GDPR, NIST AI RMF 1.1, ISO 42001, SOC2, CCPA
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ── Enums ─────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    NONE     = "none"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    DECISION        = "DECISION"
    DATA_ACCESS     = "DATA_ACCESS"
    EXTERNAL_WRITE  = "EXTERNAL_WRITE"
    TOOL_USE        = "TOOL_USE"
    API_CALL        = "API_CALL"
    HUMAN_HANDOFF   = "HUMAN_HANDOFF"
    SESSION_END     = "SESSION_END"


class Framework(str, Enum):
    EU_AI_ACT  = "EU_AI_ACT"
    GDPR       = "GDPR"
    NIST_RMF   = "NIST_RMF"
    ISO_42001  = "ISO_42001"
    SOC2       = "SOC2"
    CCPA       = "CCPA"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class FrameworkFinding:
    framework: str
    risk_level: RiskLevel
    articles: list[str]          # e.g. ["Article 12", "Article 14"]
    obligations: list[str]       # what the law requires
    violated: bool
    notes: str = ""


@dataclass
class RiskAssessment:
    event_id: str
    action_type: str
    overall_risk: RiskLevel
    blocked: bool
    reason: str
    recommendation: str
    findings: list[FrameworkFinding]
    requires_human_oversight: bool
    requires_logging: bool
    requires_explanation: bool
    confidence: float            # 0.0–1.0
    disclaimer: str = (
        "LexAgent provides compliance intelligence, not legal advice. "
        "Consult a qualified attorney for specific legal opinions."
    )


# ── Framework rule bases ───────────────────────────────────────────────────────

# Each rule: (condition_fn, risk_level, articles, obligations, notes)
# condition_fn receives the AgentEvent dict

EU_AI_ACT_RULES = [

    # Article 6 + Annex III — High-risk system categories
    {
        "id": "EU_HIGHRISK_EMPLOYMENT",
        "description": "Automated decisions affecting employment, work management, access to self-employment",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 6", "Annex III §3"],
        "obligations": [
            "System must be registered in EU AI Act database",
            "Conformity assessment required before deployment",
            "Technical documentation per Article 11",
            "Automatic logging per Article 12",
            "Human oversight per Article 14",
            "Accuracy, robustness and cybersecurity per Article 15",
        ],
        "triggers": lambda e: _decision_mentions(e, [
            "hire", "fire", "employ", "dismiss", "salary", "promotion",
            "performance", "recruit", "job", "contract", "work", "termination"
        ]),
    },
    {
        "id": "EU_HIGHRISK_CREDIT",
        "description": "Creditworthiness assessment or credit scoring",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 6", "Annex III §5b"],
        "obligations": [
            "Conformity assessment required",
            "Article 12 automatic logging mandatory",
            "Article 14 human oversight mandatory",
            "Article 13 transparency obligations",
            "Article 10 training data governance",
        ],
        "triggers": lambda e: _decision_mentions(e, [
            "credit", "loan", "lending", "mortgage", "score", "creditworthiness",
            "borrow", "finance", "debt", "repay", "default", "approve", "deny"
        ]),
    },
    {
        "id": "EU_HIGHRISK_INSURANCE",
        "description": "Risk assessment in life/health insurance",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 6", "Annex III §5c"],
        "obligations": [
            "Conformity assessment required",
            "Automatic logging per Article 12",
            "Human oversight per Article 14",
        ],
        "triggers": lambda e: _decision_mentions(e, [
            "insurance", "premium", "coverage", "policy", "health", "life insurance",
            "claim", "underwrite", "actuarial"
        ]),
    },
    {
        "id": "EU_HIGHRISK_BIOMETRIC",
        "description": "Biometric identification or categorisation",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 6", "Annex III §1", "Article 5 §1(a)"],
        "obligations": [
            "Real-time biometric ID in public spaces: PROHIBITED except narrow exceptions",
            "Post-remote biometric ID: requires prior authorisation",
            "Conformity assessment mandatory",
        ],
        "triggers": lambda e: _any_mention(e, [
            "biometric", "fingerprint", "iris", "voice recognition",
            "facial_recognition", "facial recognition", "identify_person",
            "identify person", "face recognition", "surveillance"
        ]),
    },
    {
        "id": "EU_HIGHRISK_EDUCATION",
        "description": "Decisions in education affecting access or assessment",
        "risk": RiskLevel.HIGH,
        "articles": ["Article 6", "Annex III §3"],
        "obligations": [
            "Logging per Article 12",
            "Human oversight per Article 14",
            "Transparency per Article 13",
        ],
        "triggers": lambda e: _decision_mentions(e, [
            "grade", "exam", "admission", "university", "school", "student",
            "assessment", "evaluate student", "academic", "test score"
        ]),
    },

    # Article 12 — Automatic logging
    {
        "id": "EU_ART12_LOGGING",
        "description": "Article 12: High-risk AI must automatically log all events",
        "risk": RiskLevel.HIGH,
        "articles": ["Article 12"],
        "obligations": [
            "Automatically record all events over system lifetime",
            "Retain logs minimum 6 months",
            "Logs must be queryable",
            "Record: inputs, outputs, operator interventions, periods of operation",
        ],
        "triggers": lambda e: e.get("type") in ["DECISION", "DATA_ACCESS", "EXTERNAL_WRITE"],
    },

    # Article 14 — Human oversight
    {
        "id": "EU_ART14_OVERSIGHT",
        "description": "Article 14: High-risk AI must enable human oversight",
        "risk": RiskLevel.HIGH,
        "articles": ["Article 14"],
        "obligations": [
            "Humans must be able to understand capabilities and limitations",
            "Humans must be able to monitor operation",
            "Humans must be able to intervene or interrupt",
            "Override mechanisms must be implemented",
        ],
        "triggers": lambda e: (
            e.get("type") == "DECISION" and
            not _decision_mentions(e, ["human", "review", "approve", "oversight", "handoff"])
        ),
    },

    # Article 5 — Prohibited practices
    {
        "id": "EU_ART5_PROHIBITED_MANIPULATION",
        "description": "Article 5: Prohibited — subliminal manipulation techniques",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 5 §1(a)"],
        "obligations": [
            "PROHIBITED: AI techniques that subliminally manipulate persons",
            "PROHIBITED: exploitation of vulnerabilities of specific groups",
        ],
        "triggers": lambda e: _any_mention(e, [
            "manipulate", "subliminal", "exploit vulnerability", "dark pattern",
            "psychological", "nudge", "coerce", "vulnerable"
        ]),
    },

    # Article 13 — Transparency
    {
        "id": "EU_ART13_TRANSPARENCY",
        "description": "Article 13: AI system interactions must be transparent",
        "risk": RiskLevel.MEDIUM,
        "articles": ["Article 13", "Article 50"],
        "obligations": [
            "Users must be informed they are interacting with AI",
            "AI-generated content must be labelled",
            "Instructions for use must be provided",
        ],
        "triggers": lambda e: _any_mention(e, [
            "user", "customer", "person", "human interaction", "chat", "response", "generate"
        ]) and e.get("type") in ["EXTERNAL_WRITE", "TOOL_USE"],
    },
]

GDPR_RULES = [

    # Article 22 — Automated decision-making
    {
        "id": "GDPR_ART22_ADM",
        "description": "Article 22: Automated decision-making with legal/significant effects",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 22 GDPR"],
        "obligations": [
            "Right NOT to be subject to solely automated decisions with significant effects",
            "Must provide meaningful information about the logic involved",
            "Must ensure right to obtain human intervention",
            "Must allow data subject to express their point of view",
            "Must allow contestation of the decision",
            "Explicit consent OR necessity for contract OR EU/member state law authorisation required",
        ],
        "triggers": lambda e: (
            e.get("type") == "DECISION" and
            _decision_mentions(e, [
                "credit", "loan", "insurance", "hire", "employ", "benefit",
                "access", "deny", "approve", "reject", "score", "profile"
            ])
        ),
    },

    # Article 5 — Data minimisation
    {
        "id": "GDPR_ART5_MINIMISATION",
        "description": "Article 5(1)(c): Data minimisation principle",
        "risk": RiskLevel.MEDIUM,
        "articles": ["Article 5(1)(c) GDPR"],
        "obligations": [
            "Only process data adequate, relevant and limited to what is necessary",
            "Define and document purpose before processing",
        ],
        "triggers": lambda e: e.get("type") == "DATA_ACCESS",
    },

    # Article 25 — Privacy by design
    {
        "id": "GDPR_ART25_PRIVACYBYDESIGN",
        "description": "Article 25: Data protection by design and by default",
        "risk": RiskLevel.MEDIUM,
        "articles": ["Article 25 GDPR"],
        "obligations": [
            "Implement appropriate technical measures by design",
            "Only process data necessary for specific purpose by default",
        ],
        "triggers": lambda e: e.get("type") in ["DATA_ACCESS", "DECISION"],
    },

    # Article 30 — Records of processing
    {
        "id": "GDPR_ART30_RECORDS",
        "description": "Article 30: Records of processing activities",
        "risk": RiskLevel.MEDIUM,
        "articles": ["Article 30 GDPR"],
        "obligations": [
            "Maintain records of all processing activities",
            "Records must include: purpose, data categories, recipients, retention periods",
            "Records available to supervisory authority on request",
        ],
        "triggers": lambda e: e.get("type") == "DATA_ACCESS",
    },

    # Article 32 — Security of processing
    {
        "id": "GDPR_ART32_SECURITY",
        "description": "Article 32: Security of processing",
        "risk": RiskLevel.HIGH,
        "articles": ["Article 32 GDPR"],
        "obligations": [
            "Implement appropriate technical and organisational security measures",
            "Pseudonymisation and encryption of personal data where appropriate",
            "Ensure ongoing confidentiality, integrity, availability",
        ],
        "triggers": lambda e: (
            e.get("type") in ["DATA_ACCESS", "EXTERNAL_WRITE"] and
            _any_mention(e, ["personal_data", "pii", "email", "passport", "ssn",
                              "social security", "bank account", "credit card",
                              "medical", "health_record", "address", "date_of_birth"])
        ),
    },

    # Special categories — Article 9
    {
        "id": "GDPR_ART9_SPECIAL",
        "description": "Article 9: Special category data processing",
        "risk": RiskLevel.CRITICAL,
        "articles": ["Article 9 GDPR"],
        "obligations": [
            "PROHIBITED unless explicit consent or specific legal basis",
            "Special categories: health, racial/ethnic origin, political opinions, religious beliefs, biometric, genetic, sexual orientation, trade union membership",
            "Data Protection Impact Assessment likely required (Article 35)",
        ],
        "triggers": lambda e: _any_mention(e, [
            "health", "medical", "diagnosis", "race", "ethnic", "religion",
            "political", "biometric", "genetic", "sexual", "union", "criminal"
        ]),
    },
]

NIST_RMF_RULES = [

    # GOVERN function
    {
        "id": "NIST_GOVERN_POLICY",
        "description": "GOVERN 1.1: AI risk management policies and procedures",
        "risk": RiskLevel.MEDIUM,
        "articles": ["NIST AI RMF GOVERN 1.1", "GOVERN 1.2"],
        "obligations": [
            "Organisational policies for AI risk management must exist",
            "Roles and responsibilities for AI risk must be defined",
            "AI risk management integrated into enterprise risk management",
        ],
        "triggers": lambda e: e.get("type") == "DECISION",
    },

    # MAP function — context and risk identification
    {
        "id": "NIST_MAP_CONTEXT",
        "description": "MAP 1.1: AI system context and impact assessment",
        "risk": RiskLevel.MEDIUM,
        "articles": ["NIST AI RMF MAP 1.1", "MAP 2.2", "MAP 5.1"],
        "obligations": [
            "Identify and document intended use contexts",
            "Assess potential impacts on individuals and society",
            "Identify affected groups including vulnerable populations",
        ],
        "triggers": lambda e: e.get("type") in ["DECISION", "DATA_ACCESS"],
    },

    # MEASURE function — bias and fairness
    {
        "id": "NIST_MEASURE_BIAS",
        "description": "MEASURE 2.5: Bias and fairness testing",
        "risk": RiskLevel.HIGH,
        "articles": ["NIST AI RMF MEASURE 2.5", "MEASURE 2.6"],
        "obligations": [
            "Test for demographic and other biases before deployment",
            "Monitor for bias during operation",
            "Document bias testing methodology and results",
            "Implement bias mitigation strategies",
        ],
        "triggers": lambda e: (
            e.get("type") == "DECISION" and
            _decision_mentions(e, [
                "hire", "credit", "loan", "benefit", "deny", "approve",
                "score", "rank", "select", "reject"
            ])
        ),
    },

    # MANAGE function — incident response
    {
        "id": "NIST_MANAGE_INCIDENT",
        "description": "MANAGE 2.4: AI incident response and recovery",
        "risk": RiskLevel.MEDIUM,
        "articles": ["NIST AI RMF MANAGE 2.4", "MANAGE 4.1"],
        "obligations": [
            "Incident response plan for AI failures must exist",
            "Mechanisms for detecting and reporting AI incidents",
            "Recovery procedures documented and tested",
        ],
        "triggers": lambda e: e.get("type") in ["DECISION", "EXTERNAL_WRITE"],
    },

    # Explainability
    {
        "id": "NIST_MEASURE_EXPLAIN",
        "description": "MEASURE 2.6: Explainability and interpretability",
        "risk": RiskLevel.HIGH,
        "articles": ["NIST AI RMF MEASURE 2.6", "GOVERN 6.1"],
        "obligations": [
            "AI decisions must be explainable to affected individuals",
            "Explanations must be meaningful and understandable",
            "Document explainability mechanisms",
        ],
        "triggers": lambda e: (
            e.get("type") == "DECISION" and
            not _decision_mentions(e, ["explanation", "reason", "because", "due to", "based on"])
        ),
    },
]

SOC2_RULES = [
    {
        "id": "SOC2_CC6_LOGICAL_ACCESS",
        "description": "CC6.1: Logical access controls for AI systems",
        "risk": RiskLevel.MEDIUM,
        "articles": ["SOC 2 CC6.1", "CC6.3"],
        "obligations": [
            "Logical access to AI systems restricted to authorised users",
            "Access provisioning and de-provisioning processes",
            "Authentication controls for AI system access",
        ],
        "triggers": lambda e: e.get("type") == "DATA_ACCESS",
    },
    {
        "id": "SOC2_CC7_MONITORING",
        "description": "CC7.2: System monitoring for anomalies",
        "risk": RiskLevel.MEDIUM,
        "articles": ["SOC 2 CC7.2", "CC7.3"],
        "obligations": [
            "Continuous monitoring for unauthorised access",
            "Anomaly detection for AI agent behaviour",
            "Incident detection and response procedures",
        ],
        "triggers": lambda e: e.get("type") in ["DECISION", "EXTERNAL_WRITE"],
    },
]

CCPA_RULES = [
    {
        "id": "CCPA_OPT_OUT",
        "description": "CCPA §1798.120: Right to opt-out of sale of personal information",
        "risk": RiskLevel.HIGH,
        "articles": ["CCPA §1798.120", "§1798.100"],
        "obligations": [
            "Do Not Sell My Personal Information mechanism required",
            "Honour opt-out requests within 15 business days",
            "Cannot discriminate against consumers who opt out",
        ],
        "triggers": lambda e: (
            e.get("type") in ["DATA_ACCESS", "EXTERNAL_WRITE"] and
            _any_mention(e, ["california", "consumer", "personal information", "sell", "share", "third party"])
        ),
    },
    {
        "id": "CCPA_DELETION",
        "description": "CCPA §1798.105: Right to deletion",
        "risk": RiskLevel.MEDIUM,
        "articles": ["CCPA §1798.105"],
        "obligations": [
            "Must delete consumer personal information upon verifiable request",
            "Notify service providers to delete as well",
        ],
        "triggers": lambda e: e.get("type") == "DATA_ACCESS" and _any_mention(e, ["delete", "remove", "erase"]),
    },
]

ISO_42001_RULES = [
    {
        "id": "ISO_42001_IMPACT",
        "description": "ISO 42001 §6.1.2: AI impact assessment",
        "risk": RiskLevel.MEDIUM,
        "articles": ["ISO/IEC 42001:2023 §6.1.2", "§8.4"],
        "obligations": [
            "Conduct AI impact assessment for significant AI systems",
            "Document intended and unintended impacts",
            "Consider impacts on individuals, groups and society",
        ],
        "triggers": lambda e: e.get("type") == "DECISION",
    },
    {
        "id": "ISO_42001_ACCOUNTABILITY",
        "description": "ISO 42001 §5.2: Organisational roles and accountability",
        "risk": RiskLevel.LOW,
        "articles": ["ISO/IEC 42001:2023 §5.2", "§5.3"],
        "obligations": [
            "Define and document AI management system roles",
            "Ensure accountability for AI system outcomes",
        ],
        "triggers": lambda e: e.get("type") in ["DECISION", "DATA_ACCESS"],
    },
]

ALL_FRAMEWORK_RULES: dict[str, list] = {
    Framework.EU_AI_ACT: EU_AI_ACT_RULES,
    Framework.GDPR:      GDPR_RULES,
    Framework.NIST_RMF:  NIST_RMF_RULES,
    Framework.SOC2:      SOC2_RULES,
    Framework.CCPA:      CCPA_RULES,
    Framework.ISO_42001: ISO_42001_RULES,
}


# ── Trigger helpers ────────────────────────────────────────────────────────────

def _text(event: dict) -> str:
    """Flatten event to lowercase searchable text."""
    import json
    try:
        return json.dumps(event).lower()
    except Exception:
        return str(event).lower()


def _decision_mentions(event: dict, keywords: list[str]) -> bool:
    if event.get("type") != "DECISION":
        return False
    return _any_mention(event, keywords)


def _any_mention(event: dict, keywords: list[str]) -> bool:
    text = _text(event)
    return any(kw.lower() in text for kw in keywords)


# ── Risk level ordering ───────────────────────────────────────────────────────

RISK_ORDER = {
    RiskLevel.NONE:     0,
    RiskLevel.LOW:      1,
    RiskLevel.MEDIUM:   2,
    RiskLevel.HIGH:     3,
    RiskLevel.CRITICAL: 4,
}


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


# ── Classifier ────────────────────────────────────────────────────────────────

class LegalBrainClassifier:
    """
    Classifies an AgentEvent against selected legal frameworks.
    Returns a RiskAssessment.
    """

    BLOCK_THRESHOLD = RiskLevel.HIGH

    def classify(self, event: dict, frameworks: list[str]) -> RiskAssessment:
        findings: list[FrameworkFinding] = []

        for fw_key in frameworks:
            try:
                fw = Framework(fw_key)
            except ValueError:
                continue

            rules = ALL_FRAMEWORK_RULES.get(fw, [])
            fw_findings = self._apply_rules(event, fw, rules)
            findings.extend(fw_findings)

        overall_risk = self._aggregate_risk(findings)
        blocked = RISK_ORDER[overall_risk] >= RISK_ORDER[self.BLOCK_THRESHOLD]

        reason = self._build_reason(findings, overall_risk)
        recommendation = self._build_recommendation(findings, event)

        requires_human_oversight = any(
            "human oversight" in " ".join(f.obligations).lower()
            for f in findings if f.violated
        )
        requires_logging = any(
            "logging" in " ".join(f.obligations).lower() or "log" in " ".join(f.articles).lower()
            for f in findings if f.violated
        )
        requires_explanation = any(
            "explain" in " ".join(f.obligations).lower()
            for f in findings if f.violated
        )

        confidence = self._confidence(event, findings)

        return RiskAssessment(
            event_id=event.get("id", "unknown"),
            action_type=event.get("type", "unknown"),
            overall_risk=overall_risk,
            blocked=blocked,
            reason=reason,
            recommendation=recommendation,
            findings=findings,
            requires_human_oversight=requires_human_oversight,
            requires_logging=requires_logging,
            requires_explanation=requires_explanation,
            confidence=confidence,
        )

    def _apply_rules(self, event: dict, framework: Framework, rules: list) -> list[FrameworkFinding]:
        findings = []
        for rule in rules:
            try:
                triggered = rule["triggers"](event)
            except Exception:
                triggered = False

            if triggered:
                findings.append(FrameworkFinding(
                    framework=framework.value,
                    risk_level=rule["risk"],
                    articles=rule["articles"],
                    obligations=rule["obligations"],
                    violated=True,
                    notes=rule["description"],
                ))

        # If no rules triggered for this framework, add a low-risk baseline finding
        if not findings:
            findings.append(FrameworkFinding(
                framework=framework.value,
                risk_level=RiskLevel.LOW,
                articles=[],
                obligations=[f"Standard {framework.value} monitoring active"],
                violated=False,
                notes="No specific obligations triggered for this action type",
            ))

        return findings

    def _aggregate_risk(self, findings: list[FrameworkFinding]) -> RiskLevel:
        if not findings:
            return RiskLevel.LOW
        result = RiskLevel.NONE
        for f in findings:
            if f.violated:
                result = _max_risk(result, f.risk_level)
        return result if result != RiskLevel.NONE else RiskLevel.LOW

    def _build_reason(self, findings: list[FrameworkFinding], overall: RiskLevel) -> str:
        violated = [f for f in findings if f.violated]
        if not violated:
            return "No compliance obligations triggered for this action."

        parts = []
        for f in violated:
            articles = ", ".join(f.articles[:2])
            parts.append(f"{f.framework} {articles}: {f.notes}")

        return " | ".join(parts[:3])  # top 3 findings in reason

    def _build_recommendation(self, findings: list[FrameworkFinding], event: dict) -> str:
        violated = [f for f in findings if f.violated]
        if not violated:
            return "Action logged. No immediate compliance actions required."

        critical = [f for f in violated if f.risk_level == RiskLevel.CRITICAL]
        high     = [f for f in violated if f.risk_level == RiskLevel.HIGH]

        recs = []

        if critical:
            f = critical[0]
            recs.append(f"CRITICAL ({f.framework}): {f.obligations[0]}")

        if high:
            f = high[0]
            recs.append(f"HIGH ({f.framework}): {f.obligations[0]}")

        # Universal recommendations based on action type
        action = event.get("type")
        if action == "DECISION":
            recs.append("Ensure decision explanation is available to the affected person.")
        if action == "DATA_ACCESS":
            recs.append("Verify lawful basis for processing before access.")
        if action == "EXTERNAL_WRITE":
            recs.append("Confirm output does not expose personal data without consent.")

        recs.append(
            "Consult a qualified attorney for jurisdiction-specific legal advice. "
            "LexAgent findings are compliance classifications, not professional legal opinions."
        )

        return " ".join(recs[:4])

    def _confidence(self, event: dict, findings: list[FrameworkFinding]) -> float:
        """
        Confidence score 0.0–1.0.
        Higher when: event is detailed, clear action type, keyword triggers are strong.
        Lower when: sparse event, ambiguous content.
        """
        base = 0.75
        payload = event.get("payload", {})

        # More payload detail → higher confidence
        if isinstance(payload, dict) and len(payload) >= 3:
            base += 0.10
        elif isinstance(payload, dict) and len(payload) == 0:
            base -= 0.20

        # Known action type
        known_types = {a.value for a in ActionType}
        if event.get("type") in known_types:
            base += 0.05

        # Multiple findings → more context
        if len([f for f in findings if f.violated]) >= 2:
            base += 0.05

        return round(min(max(base, 0.0), 1.0), 2)
