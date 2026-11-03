from strdeob.xorbrute import brute_force
from tests.fixtures import XOR_KEY, XOR_URL, sample_buffer


def test_single_byte_key_recovered():
    hits = brute_force(sample_buffer(), min_length=4, max_keylen=1)
    assert hits
    keys = {h.key for h in hits}
    assert f"0x{XOR_KEY:02x}" in keys
    hit = next(h for h in hits if h.key == f"0x{XOR_KEY:02x}")
    assert any(XOR_URL in i.value for i in hit.iocs)


def test_disabled_when_keylen_zero():
    assert brute_force(sample_buffer(), max_keylen=0) == []


def test_quiet_on_empty_input():
    assert brute_force(b"", max_keylen=1) == []


def test_multibyte_recovers_repeating_key():
    key = bytes([0x13, 0x37])
    plain = b"connect to http://multi.example.com/c2 every 60 seconds then sleep " * 2
    data = bytes(b ^ key[i % 2] for i, b in enumerate(plain))
    hits = brute_force(data, min_length=4, max_keylen=2)
    assert any("multi.example.com" in i.value for h in hits for i in h.iocs)
