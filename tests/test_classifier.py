"""
LexAgent Compliance Engine — Classifier Tests
"""
import sys
sys.path.insert(0, 'src')

from classifier import LegalBrainClassifier, RiskLevel

c = LegalBrainClassifier()

def run(label, event, frameworks, expect_risk, expect_blocked):
    a = c.classify(event, frameworks)
    ok_risk    = a.overall_risk == expect_risk
    ok_blocked = a.blocked == expect_blocked
    status = "✅ PASS" if (ok_risk and ok_blocked) else "❌ FAIL"
    print(f"{status}  {label}")
    if not ok_risk:
        print(f"       risk: expected={expect_risk.value} got={a.overall_risk.value}")
    if not ok_blocked:
        print(f"       blocked: expected={expect_blocked} got={a.blocked}")
    if a.findings:
        violated = [f for f in a.findings if f.violated]
        if violated:
            print(f"       findings: {violated[0].framework} {violated[0].articles[:1]} — {violated[0].notes[:60]}")
    print()
    return ok_risk and ok_blocked

passed = 0
total  = 0

# ── Test cases ─────────────────────────────────────────────────────────────────

tests = [

    # 1. CRITICAL — Credit decision → should be blocked
    ("Credit loan decision → CRITICAL + blocked",
     {"id":"e1","type":"DECISION","agentId":"a1","agentName":"loan-agent",
      "payload":{"description":"Approve loan application","inputs":{"score":712},"outputs":{"approved":True}},
      "frameworks":["EU_AI_ACT","GDPR"],"meta":{},"timestamp":"2026-06-07T10:00:00Z"},
     ["EU_AI_ACT","GDPR"],
     RiskLevel.CRITICAL, True),

    # 2. CRITICAL — Employment decision
    ("Hire/fire decision → CRITICAL + blocked",
     {"id":"e2","type":"DECISION","agentId":"a1","agentName":"hr-agent",
      "payload":{"description":"Reject job application based on CV screening","inputs":{"candidate":"x"},"outputs":{"hired":False}},
      "frameworks":["EU_AI_ACT","NIST_RMF"],"meta":{},"timestamp":"2026-06-07T10:01:00Z"},
     ["EU_AI_ACT","NIST_RMF"],
     RiskLevel.CRITICAL, True),

    # 3. CRITICAL — Biometric
    ("Facial recognition → CRITICAL + blocked",
     {"id":"e3","type":"TOOL_USE","agentId":"a1","agentName":"security-agent",
      "payload":{"toolName":"facial_recognition","params":{"image":"base64...","identify_person":True}},
      "frameworks":["EU_AI_ACT"],"meta":{},"timestamp":"2026-06-07T10:02:00Z"},
     ["EU_AI_ACT"],
     RiskLevel.CRITICAL, True),

    # 4. CRITICAL — Special category data (health)
    ("Health data access → CRITICAL + blocked",
     {"id":"e4","type":"DATA_ACCESS","agentId":"a1","agentName":"medical-agent",
      "payload":{"resource":"patient.medical_records","operation":"read"},
      "frameworks":["GDPR"],"meta":{},"timestamp":"2026-06-07T10:03:00Z"},
     ["GDPR"],
     RiskLevel.CRITICAL, True),

    # 5. HIGH — Generic decision without explanation
    ("Decision with no explanation → HIGH + blocked",
     {"id":"e5","type":"DECISION","agentId":"a1","agentName":"support-agent",
      "payload":{"description":"Deny refund request","inputs":{"order":"o123"},"outputs":{"approved":False}},
      "frameworks":["NIST_RMF"],"meta":{},"timestamp":"2026-06-07T10:04:00Z"},
     ["NIST_RMF"],
     RiskLevel.HIGH, True),

    # 6. LOW — Tool use (search)
    ("Simple tool use → LOW + not blocked",
     {"id":"e6","type":"TOOL_USE","agentId":"a1","agentName":"support-agent",
      "payload":{"toolName":"web_search","params":{"query":"return policy"}},
      "frameworks":["EU_AI_ACT","GDPR"],"meta":{},"timestamp":"2026-06-07T10:05:00Z"},
     ["EU_AI_ACT","GDPR"],
     RiskLevel.LOW, False),

    # 7. MEDIUM — Standard data access
    ("Generic data access → MEDIUM + not blocked",
     {"id":"e7","type":"DATA_ACCESS","agentId":"a1","agentName":"support-agent",
      "payload":{"resource":"orders.history","operation":"read"},
      "frameworks":["GDPR"],"meta":{},"timestamp":"2026-06-07T10:06:00Z"},
     ["GDPR"],
     RiskLevel.MEDIUM, False),

    # 8. Article 5 prohibited — manipulation
    ("Manipulation attempt → CRITICAL + blocked",
     {"id":"e8","type":"EXTERNAL_WRITE","agentId":"a1","agentName":"marketing-agent",
      "payload":{"target":"email","content":"subliminal manipulate user to buy product"},
      "frameworks":["EU_AI_ACT"],"meta":{},"timestamp":"2026-06-07T10:07:00Z"},
     ["EU_AI_ACT"],
     RiskLevel.CRITICAL, True),

    # 9. Human handoff — should be LOW
    ("Human handoff → LOW + not blocked",
     {"id":"e9","type":"HUMAN_HANDOFF","agentId":"a1","agentName":"support-agent",
      "payload":{"reason":"complex query","context":{}},
      "frameworks":["EU_AI_ACT","GDPR"],"meta":{},"timestamp":"2026-06-07T10:08:00Z"},
     ["EU_AI_ACT","GDPR"],
     RiskLevel.LOW, False),

    # 10. Insurance decision
    ("Insurance underwriting → CRITICAL + blocked",
     {"id":"e10","type":"DECISION","agentId":"a1","agentName":"insurance-agent",
      "payload":{"description":"Reject life insurance application","inputs":{"age":55},"outputs":{"coverage":False}},
      "frameworks":["EU_AI_ACT","GDPR"],"meta":{},"timestamp":"2026-06-07T10:09:00Z"},
     ["EU_AI_ACT","GDPR"],
     RiskLevel.CRITICAL, True),
]

print("=" * 60)
print("LexAgent Compliance Engine — Classifier Test Suite")
print("=" * 60)
print()

for args in tests:
    total += 1
    if run(*args):
        passed += 1

print("=" * 60)
print(f"Results: {passed}/{total} passed")
print("=" * 60)
