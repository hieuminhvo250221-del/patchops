"""Data contracts and Devin patch artifact models for PatchOps."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ProductItem(BaseModel):
    """Validated downstream product record with deterministic idempotency hash."""

    model_config = ConfigDict(str_strip_whitespace=True)

    sku: str = Field(..., min_length=1, description="Unique product SKU identifier.")
    title: str = Field(..., min_length=1, description="Product display title.")
    price: float = Field(..., gt=0, description="Product unit price; must be strictly positive.")

    @field_validator("sku", "title")
    @classmethod
    def _reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Field must not be blank.")
        return value.strip()

    @property
    def content_hash(self) -> str:
        """Deterministic SHA-256 digest used as an idempotency key for downstream writes."""
        canonical_payload = json.dumps(
            {
                "sku": self.sku,
                "title": self.title,
                "price": f"{self.price:.4f}",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


class DevinPatchArtifacts(BaseModel):
    """Structured diagnostic bundle dispatched to Devin for automated parser remediation."""

    incident_fingerprint: str = Field(
        ...,
        min_length=1,
        description="Deterministic hash identifying the class of parser failure.",
    )
    failing_raw_html: str = Field(
        ...,
        description="Raw HTML payload that triggered the circuit breaker.",
    )
    last_good_dom: str = Field(
        default="",
        description="Most recent raw HTML payload that parsed and validated cleanly.",
    )
    schema_contract: dict[str, Any] = Field(
        ...,
        description="JSON Schema generated from the target Pydantic model contract.",
    )
    parser_source: str = Field(
        ...,
        description="Exact Python source code of the failing parser function.",
    )
    error_summary: str = Field(
        default="",
        description="Human-readable summary of validation or extraction errors.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the artifact bundle was captured.",
    )


class DLQEntry(BaseModel):
    """Quarantined raw payload held in the Dead Letter Queue pending patch verification."""

    raw_html: str = Field(..., description="Original unmodified HTML response body.")
    incident_fingerprint: str = Field(..., description="Incident fingerprint associated with this failure.")
    error_reason: str = Field(..., description="Reason the payload was quarantined.")
    url: str = Field(default="", description="Optional source URL of the scraped page.")
    quarantined_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the payload entered the DLQ.",
    )
