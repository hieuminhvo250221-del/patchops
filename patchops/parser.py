"""Reference BeautifulSoup4 HTML parser for product catalog pages."""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

_PRICE_CLEAN_RE = re.compile(r"[^\d.\-]")


def _extract_price(raw_text: str | None) -> float | None:
    """Normalize a currency string (e.g. '$1,299.99') into a float, or None if invalid."""
    if raw_text is None:
        return None
    cleaned = _PRICE_CLEAN_RE.sub("", raw_text.strip())
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def parse_products(html: str) -> list[dict[str, Any]]:
    """Extract raw product dictionaries from `.product-card` DOM elements.

    Expected DOM selectors:
      - Container: `.product-card`
      - SKU:       `.sku`
      - Title:     `.title`
      - Price:     `.price`
    """
    soup = BeautifulSoup(html, "html.parser")
    cards = soup.select(".product-card")
    extracted: list[dict[str, Any]] = []

    for card in cards:
        sku_el = card.select_one(".sku")
        title_el = card.select_one(".title")
        price_el = card.select_one(".price")

        extracted.append(
            {
                "sku": sku_el.get_text(strip=True) if sku_el else None,
                "title": title_el.get_text(strip=True) if title_el else None,
                "price": _extract_price(price_el.get_text(strip=True)) if price_el else None,
            }
        )

    return extracted
