"""Reconstruct fixed-stride "stacked" strings.

Some samples build a string one spaced-out byte at a time (a classic being a URL
written one character per push, interleaved with filler). This walks the buffer
at strides 2..N and keeps a reconstructed run only when it reveals an IOC, so
ordinary text sampled every other byte is not reported as noise.
"""

from __future__ import annotations

from .iocs import Ioc, extract_iocs, has_strong

_PRINTABLE = set(range(0x20, 0x7F))


def reconstruct(
    data: bytes, min_length: int = 4, max_stride: int = 4
) -> list[tuple[str, list[Ioc]]]:
    """Return ``(reconstructed_string, iocs)`` for stride-2..N runs with an IOC."""
    results: list[tuple[str, list[Ioc]]] = []
    seen: set[str] = set()

    for stride in range(2, max_stride + 1):
        for start in range(stride):
            for run in _runs(data, start, stride, min_length):
                iocs = extract_iocs(run)
                if has_strong(iocs) and run not in seen:
                    seen.add(run)
                    results.append((run, iocs))
    return results


def _runs(data: bytes, start: int, stride: int, min_length: int) -> list[str]:
    runs: list[str] = []
    current = bytearray()
    i = start
    while i < len(data):
        byte = data[i]
        if byte in _PRINTABLE:
            current.append(byte)
        else:
            if len(current) >= min_length:
                runs.append(current.decode("ascii"))
            current.clear()
        i += stride
    if len(current) >= min_length:
        runs.append(current.decode("ascii"))
    return runs
