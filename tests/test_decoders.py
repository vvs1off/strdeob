import base64

from strdeob.decoders import decode_string


def _values(decodings):
    return {d.value for d in decodings}


def _methods(decodings):
    return {d.method for d in decodings}


def test_base64_url_recovered():
    token = base64.b64encode(b"http://evil-c2.example.com/gate.php").decode()
    out = decode_string(token)
    assert "base64" in _methods(out)
    assert "http://evil-c2.example.com/gate.php" in _values(out)


def test_hex_path_recovered():
    token = b"/etc/cron.d/backdoor".hex()
    out = decode_string(token)
    assert "hex" in _methods(out)
    assert "/etc/cron.d/backdoor" in _values(out)


def test_rot13_domain_recovered():
    # ROT13 of "malware-c2.ru"
    out = decode_string("znyjner-p2.eh")
    assert "rot13" in _methods(out)
    assert "malware-c2.ru" in _values(out)


def test_reverse_url_recovered():
    out = decode_string("http://evil.site/payload"[::-1])
    assert "reverse" in _methods(out)
    assert "http://evil.site/payload" in _values(out)


def test_plain_text_yields_no_noise():
    # An ordinary sentence should not produce IOC-gated rot/reverse decodings.
    out = decode_string("the quick brown fox jumps over")
    assert all(d.method in {"base64", "hex"} for d in out)
