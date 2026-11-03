from strdeob.stacked import reconstruct
from tests.fixtures import STACKED_URL, sample_buffer


def test_fixed_stride_url_recovered():
    found = reconstruct(sample_buffer(), min_length=4)
    values = [text for text, _ in found]
    assert STACKED_URL in values


def test_only_ioc_bearing_runs_kept():
    # Stride-2 sampling of ordinary bytes should not be reported without an IOC.
    data = bytes(range(0x41, 0x41 + 40))  # "ABC...": contiguous, no stacked IOC
    assert reconstruct(data, min_length=4) == []
