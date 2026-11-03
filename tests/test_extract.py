from strdeob.extract import extract_strings


def test_ascii_runs_respect_min_length():
    data = b"\x00hi\x00there is a longer run\x00"
    out = extract_strings(data, min_length=4)
    assert "there is a longer run" in out
    assert "hi" not in out


def test_utf16le_run_recovered():
    data = "WIDE".encode("utf-16-le")
    assert "WIDE" in extract_strings(data, min_length=4)


def test_non_printable_breaks_runs():
    data = b"good\x01bad"
    out = extract_strings(data, min_length=3)
    assert "good" in out
    assert "bad" in out
