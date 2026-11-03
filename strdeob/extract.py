"""Extract printable string runs from raw bytes."""

from __future__ import annotations

_PRINTABLE = set(range(0x20, 0x7F))


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Return ASCII and UTF-16LE printable runs of at least ``min_length`` chars."""
    out: list[str] = []
    out.extend(_ascii_runs(data, min_length))
    out.extend(_utf16le_runs(data, min_length))
    return out


def _ascii_runs(data: bytes, min_length: int) -> list[str]:
    runs: list[str] = []
    current = bytearray()
    for byte in data:
        if byte in _PRINTABLE:
            current.append(byte)
        else:
            if len(current) >= min_length:
                runs.append(current.decode("ascii"))
            current.clear()
    if len(current) >= min_length:
        runs.append(current.decode("ascii"))
    return runs


def _utf16le_runs(data: bytes, min_length: int) -> list[str]:
    runs: list[str] = []
    current = bytearray()
    for i in range(0, len(data) - 1, 2):
        low, high = data[i], data[i + 1]
        if high == 0 and low in _PRINTABLE:
            current.append(low)
        else:
            if len(current) >= min_length:
                runs.append(current.decode("ascii"))
            current.clear()
    if len(current) >= min_length:
        runs.append(current.decode("ascii"))
    return runs
