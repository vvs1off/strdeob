"""Extract indicators of compromise (IOCs) from recovered text."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# Indicators specific enough that they do not appear by chance in random bytes.
# A bare domain can, so brute-force passes (XOR, stacked) gate on these instead.
STRONG_CATEGORIES = frozenset({"url", "email", "ipv4", "registry", "windows_path", "unix_path"})


def has_strong(iocs: Iterable[Ioc]) -> bool:
    return any(i.category in STRONG_CATEGORIES for i in iocs)


# Ranking weights: URLs, IPs and emails are near-impossible in random bytes;
# paths and registry keys are specific; a bare domain is weak evidence.
_CATEGORY_WEIGHT = {
    "url": 100,
    "ipv4": 100,
    "email": 100,
    "registry": 20,
    "windows_path": 20,
    "unix_path": 20,
    "domain": 1,
}


def ioc_weight(iocs: Iterable[Ioc]) -> int:
    return sum(_CATEGORY_WEIGHT.get(i.category, 1) for i in iocs)


# A pragmatic TLD allow-list so "kernel32.dll" or "config.ini" is not mistaken
# for a domain. Extend as needed; this covers the common malware C2 TLDs.
_TLDS = (
    "com|net|org|io|co|info|biz|top|xyz|online|site|club|pro|dev|app|me|cc|"
    "ru|cn|de|uk|us|eu|br|in|ir|su|tk|ml|ga|cf|gq|pw|to|ws|nl|fr|it|pl"
)

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]{3,}", re.IGNORECASE)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("registry", re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>]+")),
    (
        "windows_path",
        re.compile(r"(?:[A-Za-z]:\\[^\s\"'<>|]*[\\.][^\s\"'<>|]+|\\\\[A-Za-z0-9._$-]+\\[^\s\"'<>|]+)"),
    ),
    ("unix_path", re.compile(r"(?:/(?:bin|etc|usr|tmp|var|opt|home|root|dev|proc)/)[^\s\"'<>]*")),
    (
        "domain",
        re.compile(
            rf"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS})\b",
            re.IGNORECASE,
        ),
    ),
]


@dataclass(frozen=True)
class Ioc:
    category: str
    value: str


def extract_iocs(text: str) -> list[Ioc]:
    """Return IOCs found in ``text``, deduplicated, with overlapping matches
    resolved in pattern order (so an IPv4 or domain inside a URL is not
    reported a second time)."""
    seen: set[tuple[str, str]] = set()
    found: list[Ioc] = []
    accepted: list[tuple[int, int]] = []
    for category, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if any(start < a_end and a_start < end for a_start, a_end in accepted):
                continue
            accepted.append((start, end))
            key = (category, match.group(0))
            if key not in seen:
                seen.add(key)
                found.append(Ioc(category, match.group(0)))
    return found


def merge_iocs(groups: Iterable[Iterable[Ioc]]) -> list[Ioc]:
    """Flatten and deduplicate several IOC lists, preserving first-seen order."""
    seen: set[tuple[str, str]] = set()
    merged: list[Ioc] = []
    for group in groups:
        for ioc in group:
            key = (ioc.category, ioc.value)
            if key not in seen:
                seen.add(key)
                merged.append(ioc)
    return merged
