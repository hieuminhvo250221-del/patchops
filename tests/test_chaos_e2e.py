"""End-to-end chaos test harness for PatchOps circuit breaker, triage, DLQ, and replay."""

from __future__ import annotations

from typing import Any

import httpx
from bs4 import BeautifulSoup

from patchops.circuit_breaker import CircuitState, IdempotentStore, PatchOpsPipeline
from patchops.models import ProductItem
from patchops.parser import _extract_price, parse_products
from patchops.triage import TriageStatus

CLOUDFLARE_403_HTML = """<!DOCTYPE html>
<html lang="en">
<head><title>Attention Required! | Cloudflare</title></head>
<body>
  <div id="cf-wrapper">
    <h1>Sorry, you have been blocked</h1>
    <p>Checking your browser before accessing the site. Ray ID: 8a1b2c3d4e5f</p>
  </div>
</body>
</html>
"""

GOLDEN_HTML = """<!DOCTYPE html>
<html lang="en">
<body>
  <section class="catalog">
    <article class="product-card">
      <span class="sku">SKU-GOLDEN-001</span>
      <h2 class="title">Classic Mechanical Keyboard</h2>
      <span class="price">$129.99</span>
    </article>
  </section>
</body>
</html>
"""

MUTATED_DOM_HTML = """<!DOCTYPE html>
<html lang="en">
<body>
  <section class="catalog">
    <article class="product-card">
      <span class="sku">SKU-MUTATED-002</span>
      <h2 class="title">Ergonomic Split Keyboard</h2>
      <span class="item-cost">$189.50</span>
    </article>
  </section>
</body>
</html>
"""


def patched_parse_products(html: str) -> list[dict[str, Any]]:
    """Patched parser supporting both legacy `.price` and mutated `.item-cost` selectors."""
    soup = BeautifulSoup(html, "html.parser")
    cards = soup.select(".product-card")
    extracted: list[dict[str, Any]] = []

    for card in cards:
        sku_el = card.select_one(".sku")
        title_el = card.select_one(".title")
        price_el = card.select_one(".price, .item-cost")

        extracted.append(
            {
                "sku": sku_el.get_text(strip=True) if sku_el else None,
                "title": title_el.get_text(strip=True) if title_el else None,
                "price": _extract_price(price_el.get_text(strip=True)) if price_el else None,
            }
        )

    return extracted


def test_cloudflare_403_triaged_out_before_parser_and_devin() -> None:
    """Test 1: Cloudflare 403 is triaged out with 0 Devin dispatches and 0 DLQ entries."""
    store = IdempotentStore()
    pipeline = PatchOpsPipeline(store=store, parser_fn=parse_products, devin_api_key="")

    result = pipeline.ingest(
        status_code=403,
        raw_html=CLOUDFLARE_403_HTML,
        headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
        url="https://shop.example.com/catalog",
    )

    assert result.triage_status == TriageStatus.WAF_BLOCK
    assert result.inserted_count == 0
    assert result.quarantined is False
    assert result.devin_dispatched is False
    assert len(pipeline.devin_dispatches) == 0
    assert len(pipeline.dlq) == 0
    assert len(store) == 0
    assert pipeline.state == CircuitState.CLOSED


def test_chaos_e2e_dom_drift_storm_protection_and_idempotent_replay() -> None:
    """Test 2: Full chaos E2E flow from golden baseline -> 10x DOM mutation -> DLQ replay."""
    store = IdempotentStore()
    pipeline = PatchOpsPipeline(
        store=store,
        parser_fn=parse_products,
        max_retries_per_incident=2,
        devin_api_key="",
    )

    # 1. Ingest golden HTML baseline.
    baseline_result = pipeline.ingest(
        status_code=200,
        raw_html=GOLDEN_HTML,
        url="https://shop.example.com/catalog/golden",
    )
    assert baseline_result.triage_status == TriageStatus.OK
    assert baseline_result.inserted_count == 1
    assert baseline_result.quarantined is False
    assert baseline_result.devin_dispatched is False
    assert len(store) == 1
    assert pipeline.last_good_dom == GOLDEN_HTML
    assert len(pipeline.dlq) == 0

    baseline_snapshot = list(store.all())

    # 2. Inject 10 mutated DOM payloads where `.price` was renamed to `.item-cost`.
    mutated_results = [
        pipeline.ingest(
            status_code=200,
            raw_html=MUTATED_DOM_HTML,
            url=f"https://shop.example.com/catalog/page-{i}",
        )
        for i in range(10)
    ]

    # Downstream DB must remain completely untouched during drift.
    assert len(store) == 1
    assert store.all() == baseline_snapshot
    assert pipeline.state == CircuitState.OPEN

    # All 10 failing payloads must be quarantined in the DLQ.
    assert len(pipeline.dlq) == 10
    assert all(r.triage_status == TriageStatus.DOM_DRIFT for r in mutated_results)
    assert all(r.quarantined is True for r in mutated_results)
    assert all(r.inserted_count == 0 for r in mutated_results)

    # Storm Protection must hard-cap Devin triggers at 2 (first 2 dispatched, next 8 suppressed).
    assert len(pipeline.devin_dispatches) == 2
    assert sum(1 for r in mutated_results if r.devin_dispatched) == 2

    # Verify all 4 required DevinPatchArtifacts fields are captured cleanly.
    artifact = pipeline.devin_dispatches[0]
    assert artifact.incident_fingerprint
    assert artifact.failing_raw_html == MUTATED_DOM_HTML
    assert artifact.last_good_dom == GOLDEN_HTML
    assert artifact.schema_contract == ProductItem.model_json_schema()
    assert "def parse_products" in artifact.parser_source

    # 3. Regression test: verify the patched parser still passes on the golden HTML fixture.
    golden_regression_records = patched_parse_products(GOLDEN_HTML)
    assert len(golden_regression_records) == 1
    golden_item = ProductItem.model_validate(golden_regression_records[0])
    assert golden_item.sku == "SKU-GOLDEN-001"
    assert golden_item.price == 129.99

    # 4. Replay DLQ with the verified patched parser.
    replay_report = pipeline.replay_dlq(patched_parse_products)

    assert replay_report.replayed_entries == 10
    assert replay_report.total_records_parsed == 10
    assert replay_report.new_rows_inserted == 1
    assert replay_report.duplicates_skipped == 9
    assert replay_report.failed_entries == 0
    assert len(pipeline.dlq) == 0
    assert pipeline.state == CircuitState.CLOSED

    # Final DB state: 1 golden baseline row + exactly 1 deduplicated replayed row.
    assert len(store) == 2
    skus = {item.sku for item in store.all()}
    assert skus == {"SKU-GOLDEN-001", "SKU-MUTATED-002"}


def test_rate_limit_429_and_devin_api_dispatch() -> None:
    """Verify HTTP 429 is triaged out and DEVIN_API_KEY dispatches to Devin Sessions API."""
    captured_requests: list[httpx.Request] = []

    def mock_transport_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"session_id": "devin-sess-123", "status": "created"})

    mock_client = httpx.Client(transport=httpx.MockTransport(mock_transport_handler))
    store = IdempotentStore()
    pipeline = PatchOpsPipeline(
        store=store,
        parser_fn=parse_products,
        max_retries_per_incident=2,
        devin_api_key="apk_test_secret_key",
        http_client=mock_client,
    )

    # HTTP 429 must never trigger Devin or enter DLQ.
    rate_limit_res = pipeline.ingest(status_code=429, raw_html="Too Many Requests")
    assert rate_limit_res.triage_status == TriageStatus.RATE_LIMIT
    assert len(captured_requests) == 0
    assert len(pipeline.dlq) == 0

    # DOM drift with DEVIN_API_KEY set must POST to https://api.devin.ai/v1/sessions.
    drift_res = pipeline.ingest(status_code=200, raw_html=MUTATED_DOM_HTML)
    assert drift_res.triage_status == TriageStatus.DOM_DRIFT
    assert drift_res.devin_dispatched is True
    assert len(captured_requests) == 1
    assert str(captured_requests[0].url) == "https://api.devin.ai/v1/sessions"
    assert captured_requests[0].headers["Authorization"] == "Bearer apk_test_secret_key"
    assert pipeline.devin_session_responses[0]["session_id"] == "devin-sess-123"
