# PatchOps

Self-healing circuit-breaker middleware for web scrapers and brittle third-party APIs, powered by [Devin](https://devin.ai).

## Architecture

```text
HTTP Response
     │
     ▼
┌─────────────────────┐   403 / 429 / 503 / WAF / CAPTCHA
│  Pre-Devin Triage   │ ──────────────────────────────────► Drop (0 ACUs burned, 0 DLQ)
└─────────┬───────────┘
          │ 2xx OK
          ▼
┌─────────────────────┐   Empty extraction or >10% validation error rate
│  Parser + Pydantic  │ ──────────────────────────────────► Trip Circuit Breaker
│  Contract Validation│                                      ├─ Halt downstream DB writes
└─────────┬───────────┘                                      ├─ Quarantine raw HTML → DLQ
          │ Valid                                            └─ Storm Protection (≤2 Devin sessions/incident)
          ▼                                                       └─ POST https://api.devin.ai/v1/sessions
┌─────────────────────┐                                               (failing HTML, last good DOM,
│   IdempotentStore   │ ◄────────── replay_dlq(patched_parser) ───────  JSON schema, parser source)
│  (SHA-256 hash key) │             (0 duplicates, 0 corrupted rows)
└─────────────────────┘
```

### Core Components

- **`patchops/models.py`**: Pydantic v2 `ProductItem` (`sku`, `title`, `price > 0`) with deterministic SHA-256 `content_hash`, `DevinPatchArtifacts`, and `DLQEntry`.
- **`patchops/triage.py`**: Pre-Devin HTTP triage (`OK`, `WAF_BLOCK`, `RATE_LIMIT`, `DOM_DRIFT`) blocking HTTP 403/429/503 and Cloudflare/CAPTCHA interstitials before parsing or dispatching Devin.
- **`patchops/parser.py`**: Reference BeautifulSoup4 parser extracting `.product-card` items (`.sku`, `.title`, `.price`).
- **`patchops/circuit_breaker.py`**: `IdempotentStore` and `PatchOpsPipeline` with anomaly thresholds (`>10%` validation error rate or empty extraction), Dead Letter Queue quarantine, Storm Protection (`max_retries_per_incident=2`), live Devin API dispatch (`DEVIN_API_KEY`), and idempotent `replay_dlq`.
- **`tests/test_chaos_e2e.py`**: End-to-end chaos harness verifying Cloudflare 403 triage, 10x DOM mutation quarantine, Storm Protection capping, golden fixture regression, and deduplicated DLQ replay.

## Quick Start

### Run with Docker Compose

```bash
docker compose up --build --exit-code-from patchops-chaos-harness
```

### Run Locally (Python 3.11+)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -v
```

Set `DEVIN_API_KEY` in your environment to enable live session dispatch to `https://api.devin.ai/v1/sessions`.
