"""Pre-Devin HTTP response triage to filter WAF walls and rate limits before parsing."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum

from pydantic import BaseModel


class TriageStatus(str, Enum):
    """Classification of an upstream HTTP response prior to or during ingestion."""

    OK = "OK"
    WAF_BLOCK = "WAF_BLOCK"
    RATE_LIMIT = "RATE_LIMIT"
    DOM_DRIFT = "DOM_DRIFT"


class TriageResult(BaseModel):
    """Result of Pre-Devin triage inspection."""

    status: TriageStatus
    status_code: int
    reason: str
    should_parse: bool
    should_dispatch_devin: bool


_WAF_BODY_SIGNATURES: tuple[str, ...] = (
    "attention required! | cloudflare",
    "cf-browser-verification",
    "cf-chl-bypass",
    "cf-turnstile",
    "checking your browser before accessing",
    "just a moment...",
    "enable javascript and cookies to continue",
    "g-recaptcha",
    "hcaptcha",
    "verify you are human",
    "access denied |",
    "ddos-guard",
    "px-captcha",
    "datadome",
)

_WAF_HEADER_MARKERS: tuple[tuple[str, str], ...] = (
    ("cf-mitigated", "challenge"),
    ("server", "cloudflare"),
)


def _normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {k.lower(): v.lower() for k, v in headers.items()}


def _has_waf_body_signature(body: str) -> str | None:
    lowered = body.lower()
    for signature in _WAF_BODY_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def triage_response(
    status_code: int,
    body: str,
    headers: Mapping[str, str] | None = None,
) -> TriageResult:
    """Classify an HTTP response before invoking the parser or Devin.

    Prevents wasting Devin ACUs attempting to "patch" a parser when the upstream
    failure is actually a WAF challenge, CAPTCHA gate, or HTTP rate limit.
    """
    norm_headers = _normalize_headers(headers)
    matched_signature = _has_waf_body_signature(body)

    if status_code == 429:
        return TriageResult(
            status=TriageStatus.RATE_LIMIT,
            status_code=status_code,
            reason="Upstream returned HTTP 429 Too Many Requests.",
            should_parse=False,
            should_dispatch_devin=False,
        )

    if status_code == 403:
        detail = f" (signature: '{matched_signature}')" if matched_signature else ""
        return TriageResult(
            status=TriageStatus.WAF_BLOCK,
            status_code=status_code,
            reason=f"Upstream returned HTTP 403 Forbidden / WAF block{detail}.",
            should_parse=False,
            should_dispatch_devin=False,
        )

    if status_code == 503:
        if matched_signature or norm_headers.get("cf-mitigated") == "challenge":
            return TriageResult(
                status=TriageStatus.WAF_BLOCK,
                status_code=status_code,
                reason="Upstream returned HTTP 503 with WAF/Cloudflare challenge markers.",
                should_parse=False,
                should_dispatch_devin=False,
            )
        return TriageResult(
            status=TriageStatus.RATE_LIMIT,
            status_code=status_code,
            reason="Upstream returned HTTP 503 Service Unavailable (transient throttling/outage).",
            should_parse=False,
            should_dispatch_devin=False,
        )

    # Catch soft WAF/CAPTCHA interstitials served with HTTP 200.
    if matched_signature is not None:
        return TriageResult(
            status=TriageStatus.WAF_BLOCK,
            status_code=status_code,
            reason=f"Detected WAF/CAPTCHA interstitial in response body ('{matched_signature}').",
            should_parse=False,
            should_dispatch_devin=False,
        )

    if norm_headers.get("cf-mitigated") == "challenge":
        return TriageResult(
            status=TriageStatus.WAF_BLOCK,
            status_code=status_code,
            reason="Detected Cloudflare challenge header (cf-mitigated: challenge).",
            should_parse=False,
            should_dispatch_devin=False,
        )

    if 200 <= status_code < 300:
        if not body.strip():
            return TriageResult(
                status=TriageStatus.DOM_DRIFT,
                status_code=status_code,
                reason="Upstream returned empty 2xx response body.",
                should_parse=True,
                should_dispatch_devin=True,
            )
        return TriageResult(
            status=TriageStatus.OK,
            status_code=status_code,
            reason="Response passed pre-Devin triage.",
            should_parse=True,
            should_dispatch_devin=False,
        )

    if status_code >= 500:
        return TriageResult(
            status=TriageStatus.RATE_LIMIT,
            status_code=status_code,
            reason=f"Upstream returned transient server error HTTP {status_code}.",
            should_parse=False,
            should_dispatch_devin=False,
        )

    return TriageResult(
        status=TriageStatus.WAF_BLOCK,
        status_code=status_code,
        reason=f"Upstream returned unexpected non-2xx HTTP {status_code}; skipping parser.",
        should_parse=False,
        should_dispatch_devin=False,
    )
