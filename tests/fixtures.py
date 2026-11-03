"""Deterministic, harmless fixtures built in pure Python.

No committed samples and nothing malicious: a single buffer is assembled in
code, embedding one of each obfuscation strdeob is meant to unwind. The
"indicators" are obvious example values (example.com / RFC 5737-style text),
present only so the decoders have something to recover.
"""

from __future__ import annotations

import base64

# Plaintext indicators the decoders should recover.
B64_URL = "http://evil-c2.example.com/gate.php"
HEX_PATH = "/etc/cron.d/backdoor"
ROT13_DOMAIN = "malware-c2.ru"
REVERSED_URL = "http://evil.site/payload"
XOR_URL = "http://xor-c2.example.net/beacon?id=1337"
XOR_KEY = 0x5A
STACKED_URL = "http://st4ck.example.org"
STACKED_FILLER = 0x01


def _rot13(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr((code - 65 + 13) % 26 + 65))
        elif 97 <= code <= 122:
            out.append(chr((code - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _stacked(text: str, filler: int, stride: int = 2) -> bytes:
    out = bytearray()
    for ch in text:
        out.append(ord(ch))
        out.extend([filler] * (stride - 1))
    return bytes(out)


def sample_buffer() -> bytes:
    sep = b"\x00\x00\x00"
    parts = [
        base64.b64encode(B64_URL.encode()),
        sep,
        HEX_PATH.encode().hex().encode(),
        sep,
        _rot13(ROT13_DOMAIN).encode(),
        sep,
        REVERSED_URL[::-1].encode(),
        sep,
        # XOR block fenced with 0x5a so the bytes become NUL once un-XORed.
        bytes([XOR_KEY, XOR_KEY]) + _xor(XOR_URL.encode(), XOR_KEY) + bytes([XOR_KEY, XOR_KEY]),
        sep,
        _stacked(STACKED_URL, STACKED_FILLER),
    ]
    return b"".join(parts)
