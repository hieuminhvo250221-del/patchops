"""Circuit breaker, Dead Letter Queue, Storm Protection, Devin dispatch, and idempotent replay."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
from collections.abc import Callable, Iterable, Mapping
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from patchops.models import DLQEntry, DevinPatchArtifacts, ProductItem
from patchops.parser import parse_products
from patchops.triage import TriageStatus, triage_response

logger = logging.getLogger(__name__)

ParserFn = Callable[[str], list[dict[str, Any]]]


class CircuitState(str, Enum):
    """Operational state of the PatchOps circuit breaker."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"


class IngestResult(BaseModel):
    """Structured outcome of a single pipeline ingestion attempt."""

    triage_status: TriageStatus
    inserted_count: int = 0
    quarantined: bool = False
    devin_dispatched: bool = False
    incident_fingerprint: str | None = None
    error_rate: float = 0.0
    reason: str = ""


class ReplayReport(BaseModel):
    """Summary of a Dead Letter Queue replay operation."""

    replayed_entries: int
    total_records_parsed: int
    new_rows_inserted: int
    duplicates_skipped: int
    failed_entries: int


class IdempotentStore:
    """Downstream database abstraction keyed by `ProductItem.content_hash`.

    Guarantees exactly-once persistence semantics so DLQ replays never create
    duplicate rows even when identical payloads are quarantined multiple times.
    """

    def __init__(self) -> None:
        self._records: dict[str, ProductItem] = {}

    def upsert(self, item: ProductItem) -> bool:
        """Insert item if its content_hash is unseen. Returns True if newly inserted."""
        key = item.content_hash
        if key in self._records:
            return False
        self._records[key] = item
        return True

    def upsert_many(self, items: Iterable[ProductItem]) -> tuple[int, int]:
        """Upsert multiple items. Returns (new_rows_inserted, duplicates_skipped)."""
        inserted = 0
        duplicates = 0
        for item in items:
            if self.upsert(item):
                inserted += 1
            else:
                duplicates += 1
        return inserted, duplicates

    def get(self, content_hash: str) -> ProductItem | None:
        """Retrieve a stored item by its content_hash."""
        return self._records.get(content_hash)

    def all(self) -> list[ProductItem]:
        """Return all stored ProductItem records in insertion order."""
        return list(self._records.values())

    def count(self) -> int:
        """Return the number of unique stored records."""
        return len(self._records)

    def __len__(self) -> int:
        return len(self._records)


class PatchOpsPipeline:
    """Self-healing circuit-breaker middleware for web scrapers and brittle APIs.

    Lifecycle:
      1. Pre-Devin Triage filters out WAF blocks (403, Cloudflare/CAPTCHA) and
         rate limits (429/503) without touching the parser, DLQ, or Devin.
      2. Parser extracts candidate records and validates them against `ProductItem`.
      3. Empty extractions or validation error rates exceeding `error_rate_threshold`
         trip the circuit breaker, halt downstream DB writes, quarantine raw HTML
         in `self.dlq`, and dispatch a Devin session capped by Storm Protection.
      4. `replay_dlq(patched_parser_fn)` replays quarantined HTML through a verified
         patch into `IdempotentStore` with zero duplicates and zero corrupted rows.
    """

    DEVIN_SESSIONS_URL: str = "https://api.devin.ai/v1/sessions"

    def __init__(
        self,
        store: IdempotentStore,
        parser_fn: ParserFn = parse_products,
        *,
        error_rate_threshold: float = 0.10,
        max_retries_per_incident: int = 2,
        devin_api_key: str | None = None,
        devin_api_url: str = DEVIN_SESSIONS_URL,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not 0.0 <= error_rate_threshold <= 1.0:
            raise ValueError("error_rate_threshold must be between 0.0 and 1.0.")
        if max_retries_per_incident < 0:
            raise ValueError("max_retries_per_incident must be >= 0.")

        self.store: IdempotentStore = store
        self.parser_fn: ParserFn = parser_fn
        self.error_rate_threshold: float = error_rate_threshold
        self.max_retries_per_incident: int = max_retries_per_incident
        self.devin_api_key: str | None = (
            devin_api_key if devin_api_key is not None else os.getenv("DEVIN_API_KEY")
        )
        self.devin_api_url: str = devin_api_url
        self._http_client: httpx.Client | None = http_client

        self.state: CircuitState = CircuitState.CLOSED
        self.dlq: list[DLQEntry] = []
        self.last_good_dom: str = ""
        self.incident_dispatch_counts: dict[str, int] = {}
        self.devin_dispatches: list[DevinPatchArtifacts] = []
        self.devin_session_responses: list[dict[str, Any]] = []

    def ingest(
        self,
        status_code: int,
        raw_html: str,
        headers: Mapping[str, str] | None = None,
        url: str = "",
    ) -> IngestResult:
        """Process a single HTTP response through triage, parsing, validation, and circuit breaking."""
        triage = triage_response(status_code=status_code, body=raw_html, headers=headers)
        if not triage.should_parse:
            logger.info(
                "Pre-Devin triage dropped response (status=%s, http=%d): %s",
                triage.status.value,
                status_code,
                triage.reason,
            )
            return IngestResult(
                triage_status=triage.status,
                inserted_count=0,
                quarantined=False,
                devin_dispatched=False,
                reason=triage.reason,
            )

        try:
            raw_records = self.parser_fn(raw_html)
        except Exception as exc:
            error_signature = f"PARSER_EXCEPTION:{type(exc).__name__}"
            return self._handle_drift(
                raw_html=raw_html,
                url=url,
                error_signature=error_signature,
                error_summary=f"Parser raised {type(exc).__name__}: {exc}",
                error_rate=1.0,
            )

        if not raw_records:
            return self._handle_drift(
                raw_html=raw_html,
                url=url,
                error_signature="EMPTY_EXTRACTION",
                error_summary="Parser returned 0 records from non-empty 2xx HTML response.",
                error_rate=1.0,
            )

        valid_items: list[ProductItem] = []
        failed_field_signatures: set[str] = set()
        error_messages: list[str] = []

        for idx, record in enumerate(raw_records):
            try:
                valid_items.append(ProductItem.model_validate(record))
            except ValidationError as exc:
                for err in exc.errors():
                    loc = ".".join(str(part) for part in err.get("loc", ()))
                    err_type = str(err.get("type", "validation_error"))
                    failed_field_signatures.add(f"{loc}:{err_type}")
                error_messages.append(f"record[{idx}]: {exc.errors()[0].get('msg', 'invalid')}")

        error_count = len(raw_records) - len(valid_items)
        error_rate = error_count / len(raw_records)

        if error_rate > self.error_rate_threshold:
            signature_parts = ",".join(sorted(failed_field_signatures)) or "VALIDATION_ERROR"
            return self._handle_drift(
                raw_html=raw_html,
                url=url,
                error_signature=f"SCHEMA_DRIFT:{signature_parts}",
                error_summary=(
                    f"Validation error rate {error_rate:.1%} exceeded threshold "
                    f"{self.error_rate_threshold:.1%}: {'; '.join(error_messages[:5])}"
                ),
                error_rate=error_rate,
            )

        # Healthy payload: close circuit, snapshot golden DOM, and persist idempotently.
        self.state = CircuitState.CLOSED
        self.last_good_dom = raw_html
        inserted, _ = self.store.upsert_many(valid_items)

        return IngestResult(
            triage_status=TriageStatus.OK,
            inserted_count=inserted,
            quarantined=False,
            devin_dispatched=False,
            error_rate=error_rate,
            reason="Ingested and validated successfully.",
        )

    def replay_dlq(self, patched_parser_fn: ParserFn) -> ReplayReport:
        """Replay all quarantined DLQ payloads through a verified patched parser.

        Validates every record strictly against `ProductItem` before writing to
        `IdempotentStore`. Guarantees zero duplicate rows and zero corrupted rows.
        """
        entries_to_replay = list(self.dlq)
        remaining_dlq: list[DLQEntry] = []

        replayed_entries = 0
        total_records_parsed = 0
        new_rows_inserted = 0
        duplicates_skipped = 0
        failed_entries = 0

        for entry in entries_to_replay:
            try:
                raw_records = patched_parser_fn(entry.raw_html)
                if not raw_records:
                    raise ValueError("Patched parser returned 0 records during DLQ replay.")
                validated_items = [ProductItem.model_validate(rec) for rec in raw_records]
            except Exception as exc:
                logger.error(
                    "DLQ replay failed for fingerprint=%s: %s",
                    entry.incident_fingerprint,
                    exc,
                )
                remaining_dlq.append(entry)
                failed_entries += 1
                continue

            inserted, duplicates = self.store.upsert_many(validated_items)
            replayed_entries += 1
            total_records_parsed += len(validated_items)
            new_rows_inserted += inserted
            duplicates_skipped += duplicates

        self.dlq = remaining_dlq
        if failed_entries == 0:
            self.parser_fn = patched_parser_fn
            self.state = CircuitState.CLOSED

        return ReplayReport(
            replayed_entries=replayed_entries,
            total_records_parsed=total_records_parsed,
            new_rows_inserted=new_rows_inserted,
            duplicates_skipped=duplicates_skipped,
            failed_entries=failed_entries,
        )

    def _compute_incident_fingerprint(self, error_signature: str) -> str:
        """Compute a deterministic incident fingerprint for Storm Protection deduplication."""
        parser_name = getattr(self.parser_fn, "__qualname__", repr(self.parser_fn))
        raw_key = f"{parser_name}|{error_signature}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    def _get_parser_source(self) -> str:
        """Extract exact Python source code of the active parser function."""
        try:
            return inspect.getsource(self.parser_fn)
        except (OSError, TypeError):
            return repr(self.parser_fn)

    def _handle_drift(
        self,
        *,
        raw_html: str,
        url: str,
        error_signature: str,
        error_summary: str,
        error_rate: float,
    ) -> IngestResult:
        """Trip the breaker, quarantine raw HTML in DLQ, and trigger Devin under Storm Protection."""
        self.state = CircuitState.OPEN
        fingerprint = self._compute_incident_fingerprint(error_signature)

        self.dlq.append(
            DLQEntry(
                raw_html=raw_html,
                incident_fingerprint=fingerprint,
                error_reason=error_summary,
                url=url,
            )
        )

        dispatched = False
        prior_dispatches = self.incident_dispatch_counts.get(fingerprint, 0)
        if prior_dispatches < self.max_retries_per_incident:
            self.incident_dispatch_counts[fingerprint] = prior_dispatches + 1
            artifacts = DevinPatchArtifacts(
                incident_fingerprint=fingerprint,
                failing_raw_html=raw_html,
                last_good_dom=self.last_good_dom,
                schema_contract=ProductItem.model_json_schema(),
                parser_source=self._get_parser_source(),
                error_summary=error_summary,
            )
            self.devin_dispatches.append(artifacts)
            self._dispatch_devin_session(artifacts)
            dispatched = True
        else:
            logger.warning(
                "Storm Protection suppressed Devin dispatch for fingerprint=%s (cap=%d reached).",
                fingerprint,
                self.max_retries_per_incident,
            )

        return IngestResult(
            triage_status=TriageStatus.DOM_DRIFT,
            inserted_count=0,
            quarantined=True,
            devin_dispatched=dispatched,
            incident_fingerprint=fingerprint,
            error_rate=error_rate,
            reason=error_summary,
        )

    def _build_devin_prompt(self, artifacts: DevinPatchArtifacts) -> str:
        """Construct the structured remediation prompt for the Devin Sessions API."""
        return (
            f"PatchOps Incident `{artifacts.incident_fingerprint}` detected DOM drift.\n"
            f"Error summary: {artifacts.error_summary}\n\n"
            f"### Target JSON Schema Contract\n"
            f"```json\n{json.dumps(artifacts.schema_contract, indent=2)}\n```\n\n"
            f"### Failing Parser Source\n"
            f"```python\n{artifacts.parser_source}\n```\n\n"
            f"### Last Known Good DOM\n"
            f"```html\n{artifacts.last_good_dom}\n```\n\n"
            f"### Failing Raw HTML\n"
            f"```html\n{artifacts.failing_raw_html}\n```\n\n"
            "Update the parser to satisfy the schema contract for both the last good DOM "
            "(regression fixture) and the failing HTML, then open a PR with passing tests."
        )

    def _dispatch_devin_session(self, artifacts: DevinPatchArtifacts) -> dict[str, Any] | None:
        """Dispatch a remediation session to the Devin API if DEVIN_API_KEY is configured."""
        if not self.devin_api_key:
            logger.info(
                "DEVIN_API_KEY not set; recorded DevinPatchArtifacts locally for fingerprint=%s.",
                artifacts.incident_fingerprint,
            )
            return None

        payload = {
            "prompt": self._build_devin_prompt(artifacts),
            "idempotent": True,
            "tags": ["patchops", f"incident:{artifacts.incident_fingerprint}"],
        }
        headers = {
            "Authorization": f"Bearer {self.devin_api_key}",
            "Content-Type": "application/json",
        }

        if self._http_client is not None:
            response = self._http_client.post(
                self.devin_api_url,
                json=payload,
                headers=headers,
            )
        else:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    self.devin_api_url,
                    json=payload,
                    headers=headers,
                )

        response.raise_for_status()
        data: dict[str, Any] = response.json()
        self.devin_session_responses.append(data)
        return data
