# LexAgent Legal Brain

FastAPI backend — AI legal risk classifier for autonomous agents.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/risk/check` | Sync risk check for high-risk actions |
| POST | `/v1/events/batch` | Async batch event ingestion |
| POST | `/v1/agents/status` | Agent compliance posture |
| POST | `/v1/reports/generate` | PDF/JSON compliance report |
| GET  | `/health` | Health check |

## Frameworks

EU AI Act · GDPR · NIST AI RMF 1.1 · ISO 42001 · SOC 2 · CCPA

## Run locally

```bash
pip install -r requirements.txt
uvicorn src.main:app --reload
```

## Deploy (Render)

Set env var: `LEXAGENT_MASTER_KEY=lxa_your_key`

## Test

```bash
python3 tests/test_classifier.py
# Results: 10/10 passed
```

## Legal notice

LexAgent provides compliance intelligence, not legal advice.
