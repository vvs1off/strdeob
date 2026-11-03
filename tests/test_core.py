import pytest

from strdeob.core import ReadError, analyze, read_file
from tests.fixtures import (
    B64_URL,
    ROT13_DOMAIN,
    STACKED_URL,
    XOR_URL,
    sample_buffer,
)


def test_report_aggregates_all_iocs():
    report = analyze(sample_buffer(), path="sample.bin", min_length=4, max_keylen=1)
    ioc_values = {i["value"] for i in report.iocs}
    assert B64_URL in ioc_values
    assert ROT13_DOMAIN in ioc_values
    assert STACKED_URL in ioc_values
    assert any(XOR_URL in v for v in ioc_values)
    assert report.is_interesting


def test_to_dict_is_json_shaped():
    report = analyze(sample_buffer())
    data = report.to_dict()
    assert set(data) >= {"path", "size", "decodings", "stacked", "xor", "iocs", "is_interesting"}


def test_clean_input_is_not_interesting():
    report = analyze(b"\x00" * 64 + b"just some harmless padding text\x00", max_keylen=1)
    assert not report.iocs
    assert not report.is_interesting


def test_read_file_bounds_size(tmp_path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 100)
    with pytest.raises(ReadError):
        read_file(str(target), max_bytes=10)


def test_read_file_missing(tmp_path):
    with pytest.raises(ReadError):
        read_file(str(tmp_path / "nope.bin"), max_bytes=1000)
