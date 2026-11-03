"""Per-string decoders: base64, hex, ROT/Caesar and reversal.

Each decoder is deliberately conservative. Base64 and hex are structural signals
strong enough to surface on their own when they decode to readable text; ROT,
Caesar and reversal are surfaced only when the transform reveals an IOC, which
keeps the output signal rather than 25 rotations of every token.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from .iocs import extract_iocs, has_strong

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

_B64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_ALPHA_RUN = re.compile(r"[A-Za-z]{3,}")


@dataclass(frozen=True)
class Decoding:
    method: str
    source: str
    value: str


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ord(ch) in _PRINTABLE)
    return printable / len(text)


def _looks_textual(text: str, min_length: int) -> bool:
    """A cheap readability test: mostly printable and containing a real word."""
    return (
        len(text) >= min_length
        and _printable_ratio(text) >= 0.9
        and _ALPHA_RUN.search(text) is not None
    )


def decode_string(text: str, min_length: int = 4) -> list[Decoding]:
    """Return interesting decodings of ``text`` across all supported methods."""
    found: list[Decoding] = []
    seen: set[tuple[str, str]] = set()

    def add(method: str, source: str, value: str) -> None:
        key = (method, value)
        if value and value != source and key not in seen:
            seen.add(key)
            found.append(Decoding(method, source, value))

    for token in _B64_RE.findall(text):
        decoded = _try_base64(token)
        if decoded is not None and (_looks_textual(decoded, min_length) or extract_iocs(decoded)):
            add("base64", token, decoded)

    for token in _HEX_RE.findall(text):
        decoded = _try_hex(token)
        if decoded is not None and (_looks_textual(decoded, min_length) or extract_iocs(decoded)):
            add("hex", token, decoded)

    # ROT13 is the common intentional transform, so any IOC (a bare domain
    # included) is enough; the other Caesar shifts are a brute sweep and only a
    # strong IOC keeps them, otherwise 24 rotations hit a short TLD by chance.
    for shift in range(1, 26):
        rotated = _caesar(text, shift)
        iocs = extract_iocs(rotated)
        if bool(iocs) if shift == 13 else has_strong(iocs):
            method = "rot13" if shift == 13 else f"caesar{shift}"
            add(method, text, rotated)

    reversed_text = text[::-1]
    if has_strong(extract_iocs(reversed_text)):
        add("reverse", text, reversed_text)

    return found


def _try_base64(token: str) -> str | None:
    padded = token + "=" * ((-len(token)) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    return raw.decode("latin-1")


def _try_hex(token: str) -> str | None:
    usable = token[: len(token) - (len(token) % 2)]
    try:
        raw = bytes.fromhex(usable)
    except ValueError:
        return None
    if not raw:
        return None
    return raw.decode("latin-1")


def _caesar(text: str, shift: int) -> str:
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr((code - 65 + shift) % 26 + 65))
        elif 97 <= code <= 122:
            out.append(chr((code - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)
