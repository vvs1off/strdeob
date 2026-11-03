"""Orchestration: turn a buffer into a deobfuscation report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .decoders import Decoding, decode_string
from .extract import extract_strings
from .iocs import Ioc, extract_iocs, merge_iocs
from .stacked import reconstruct
from .xorbrute import XorHit, brute_force

_MAX_DECODINGS = 200


class ReadError(Exception):
    """Raised when the input file cannot be read."""


@dataclass
class DeobReport:
    path: str
    size: int
    decodings: list[dict]
    stacked: list[dict]
    xor: list[dict]
    iocs: list[dict] = field(default_factory=list)

    @property
    def is_interesting(self) -> bool:
        return bool(self.decodings or self.stacked or self.xor or self.iocs)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["is_interesting"] = self.is_interesting
        return data


def _ioc_dicts(iocs: list[Ioc]) -> list[dict]:
    return [{"category": i.category, "value": i.value} for i in iocs]


def read_file(path: str, max_bytes: int) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ReadError(f"cannot read {path}: {exc}") from exc
    if len(data) > max_bytes:
        raise ReadError(f"{path} is larger than the {max_bytes}-byte limit")
    return data


def analyze(
    data: bytes,
    path: str = "<buffer>",
    min_length: int = 4,
    max_keylen: int = 1,
) -> DeobReport:
    """Analyse ``data`` and return a :class:`DeobReport`."""
    plain = extract_strings(data, min_length)
    plain_set = set(plain)

    decodings: list[Decoding] = []
    for string in plain:
        decodings.extend(decode_string(string, min_length))
    decodings = decodings[:_MAX_DECODINGS]

    stacked = [
        (text, iocs)
        for text, iocs in reconstruct(data, min_length)
        if text not in plain_set
    ]

    xor_hits: list[XorHit] = brute_force(data, min_length, max_keylen=max_keylen)

    ioc_groups: list[list[Ioc]] = [extract_iocs(s) for s in plain]
    ioc_groups.extend(extract_iocs(d.value) for d in decodings)
    ioc_groups.extend(iocs for _, iocs in stacked)
    ioc_groups.extend(hit.iocs for hit in xor_hits)
    iocs = merge_iocs(ioc_groups)

    return DeobReport(
        path=path,
        size=len(data),
        decodings=[{"method": d.method, "source": d.source, "value": d.value} for d in decodings],
        stacked=[{"value": text, "iocs": _ioc_dicts(iocs)} for text, iocs in stacked],
        xor=[
            {
                "key": hit.key,
                "keylen": hit.keylen,
                "score": hit.score,
                "strings": hit.strings,
                "iocs": _ioc_dicts(hit.iocs),
            }
            for hit in xor_hits
        ],
        iocs=_ioc_dicts(iocs),
    )
