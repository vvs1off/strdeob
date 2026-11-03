import json

from strdeob.cli import EXIT_ERROR, EXIT_OK, main
from tests.fixtures import B64_URL, sample_buffer


def test_table_output_runs(tmp_path, capsys):
    target = tmp_path / "sample.bin"
    target.write_bytes(sample_buffer())
    assert main([str(target)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "iocs" in out


def test_json_output_is_valid(tmp_path, capsys):
    target = tmp_path / "sample.bin"
    target.write_bytes(sample_buffer())
    assert main([str(target), "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["is_interesting"] is True
    assert any(i["value"] == B64_URL for i in data["iocs"])


def test_fail_on_ioc_sets_exit_code(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(sample_buffer())
    assert main([str(target), "--fail-on-ioc"]) == EXIT_ERROR


def test_missing_file_reports_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope.bin")]) == EXIT_ERROR
    assert "strdeob:" in capsys.readouterr().err


def test_usage_error_on_bad_min_str(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    try:
        main([str(target), "--min-str", "0"])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit")
