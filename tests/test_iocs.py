from strdeob.iocs import extract_iocs, merge_iocs


def _values(iocs):
    return {i.value for i in iocs}


def _by_category(iocs):
    return {(i.category, i.value) for i in iocs}


def test_extracts_each_category():
    text = (
        "visit http://c2.example.com/x mail a@b.example.org from 203.0.113.9 "
        r"key HKLM\Software\Evil path C:\Windows\Temp\x.exe unix /etc/passwd "
        "domain bad-domain.ru end"
    )
    cats = {i.category for i in extract_iocs(text)}
    assert {"url", "email", "ipv4", "registry", "windows_path", "unix_path", "domain"} <= cats


def test_ipv4_inside_url_not_double_reported():
    iocs = extract_iocs("http://203.0.113.9/payload")
    assert ("url", "http://203.0.113.9/payload") in _by_category(iocs)
    assert "203.0.113.9" not in _values(iocs)


def test_non_tld_is_not_a_domain():
    iocs = extract_iocs("loads kernel32.dll and config.ini")
    assert all(i.category != "domain" for i in iocs)


def test_merge_dedupes_preserving_order():
    a = extract_iocs("http://a.example.com")
    b = extract_iocs("http://a.example.com and http://b.example.com")
    merged = merge_iocs([a, b])
    assert [i.value for i in merged] == ["http://a.example.com", "http://b.example.com"]
