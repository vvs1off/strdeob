"""XOR brute force: recover strings hidden behind an XOR mask.

Single-byte keys are brute-forced exhaustively (cheap and complete). Repeating
keys of length 2..N are recovered with a per-column printable-maximisation
heuristic rather than a full key-space search, so the cost stays linear in the
buffer size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .extract import extract_strings
from .iocs import Ioc, extract_iocs, has_strong, ioc_weight, merge_iocs

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_MAX_STRINGS_PER_KEY = 25
_ALPHA_RUN = re.compile(r"[A-Za-z]{3,}")


@dataclass
class XorHit:
    key: str
    keylen: int
    score: int
    strings: list[str]
    iocs: list[Ioc]


def _xor(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        table = bytes(i ^ key[0] for i in range(256))
        return data.translate(table)
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def _meaningful(strings: list[str]) -> list[str]:
    """Readable strings: a real word plus enough character variety that a run of
    repeated filler (e.g. a block of identical bytes un-masked to one letter) is
    not mistaken for recovered text."""
    return [s for s in strings if _ALPHA_RUN.search(s) and len(set(s)) >= 4]


def _score(meaningful: list[str], iocs: list[Ioc]) -> int:
    return ioc_weight(iocs) + len(meaningful)


def _english_score(values: bytes) -> float:
    """Reward column bytes that look like English text, penalise non-printable.

    Space and lowercase letters dominate real text, so weighting them breaks the
    ties that a bare printable count leaves on short, low-variety plaintext.
    """
    score = 0.0
    for b in values:
        if b == 0x20:
            score += 6.0
        elif 0x61 <= b <= 0x7A:
            score += 3.0
        elif 0x41 <= b <= 0x5A:
            score += 1.5
        elif 0x30 <= b <= 0x39:
            score += 1.0
        elif b in _PRINTABLE:
            score += 0.3
        else:
            score -= 5.0
    return score


def _recover_key(data: bytes, keylen: int) -> bytes:
    """Recover a repeating key by scoring each column for English-likeness."""
    key = bytearray(keylen)
    for pos in range(keylen):
        column = data[pos::keylen]
        best_byte, best_score = 0, float("-inf")
        for candidate in range(256):
            score = _english_score(bytes(b ^ candidate for b in column))
            if score > best_score:
                best_byte, best_score = candidate, score
        key[pos] = best_byte
    return bytes(key)


def brute_force(
    data: bytes,
    min_length: int = 4,
    max_keylen: int = 1,
    max_hits: int = 5,
) -> list[XorHit]:
    """Return XOR keys that un-mask at least one IOC, ranked by IOC count.

    Gating on a recovered IOC keeps the pass quiet on files that are not
    XOR-obfuscated and avoids reporting incidental semi-text. ``max_keylen`` of 0
    disables the pass entirely.
    """
    if max_keylen < 1 or not data:
        return []

    hits: list[XorHit] = []

    def consider(key_label: str, keylen: int, decoded: bytes) -> None:
        strings = extract_strings(decoded, min_length)
        iocs = merge_iocs(extract_iocs(s) for s in strings)
        if has_strong(iocs):
            hits.append(
                XorHit(
                    key=key_label,
                    keylen=keylen,
                    score=_score(_meaningful(strings), iocs),
                    strings=_meaningful(strings)[:_MAX_STRINGS_PER_KEY],
                    iocs=iocs,
                )
            )

    for key in range(1, 256):
        consider(f"0x{key:02x}", 1, _xor(data, bytes([key])))

    for keylen in range(2, max_keylen + 1):
        key = _recover_key(data, keylen)
        if any(key):
            consider("0x" + key.hex(), keylen, _xor(data, key))

    hits.sort(key=lambda h: (-h.score, h.keylen, h.key))
    return hits[:max_hits]
