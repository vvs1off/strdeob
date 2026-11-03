# strdeob

Static string deobfuscator and IOC extractor for malware triage.

Malware rarely leaves its URLs, IPs and paths in the clear — they are base64 or
hex encoded, ROT'd, reversed, XOR-masked or built one byte at a time. `strdeob`
tries the common static obfuscations against a file, then rolls every recovered
candidate up into one deduplicated IOC list. Table output by default, `--json`
for your pipeline. It only ever reads the file you point it at: no execution, no
network.

![demo](assets/demo.gif)

## Features

- Printable string extraction (ASCII and UTF-16LE)
- Per-string decoders: **base64**, **hex**, **ROT13 / Caesar**, **reversal**
- **Single-byte XOR** brute force, and short **repeating-key XOR** recovery
- **Stacked strings**: fixed-stride (2–4) reconstruction of spaced-out indicators
- **IOC extraction** — URL, email, IPv4, domain, Windows/Unix path, registry key
  — aggregated and deduplicated across every recovered candidate
- Signal over noise: brute-force passes surface a key only when it reveals a
  strong indicator, not an incidental match
- Human-readable output by default, `--json` with a stable schema
- No telemetry, no network calls

## Install

```sh
pipx install strdeob
```

Or from source:

```sh
git clone https://github.com/vvs1off/strdeob
cd strdeob
pipx install .
```

## Usage

```sh
strdeob sample.bin                      # readable tables
strdeob sample.bin --xor-max-keylen 2   # also try 2-byte repeating XOR keys
strdeob sample.bin --json | jq .iocs    # structured output
strdeob sample.bin --fail-on-ioc && echo "nothing recovered"
```

Example against a crafted test buffer:

```
strdeob sample.bin  (232 bytes)

decodings
 method   value
 base64   http://evil-c2.example.com/gate.php
 hex      /etc/cron.d/backdoor
 rot13    malware-c2.ru
 reverse  http://evil.site/payload

xor keys
 key   len  recovered
 0x5a    1  http://xor-c2.example.net/beacon?id=1337

stacked strings
 http://st4ck.example.org

iocs
 url        http://evil-c2.example.com/gate.php
 unix_path  /etc/cron.d/backdoor
 domain     malware-c2.ru
 url        http://evil.site/payload
 url        http://st4ck.example.org
 url        http://xor-c2.example.net/beacon?id=1337
```

JSON (trimmed):

```json
{
  "path": "sample.bin",
  "size": 232,
  "decodings": [
    { "method": "base64", "source": "aHR0cDov...", "value": "http://evil-c2.example.com/gate.php" }
  ],
  "stacked": [
    { "value": "http://st4ck.example.org", "iocs": [{ "category": "url", "value": "http://st4ck.example.org" }] }
  ],
  "xor": [
    { "key": "0x5a", "keylen": 1, "score": 101, "strings": ["..."],
      "iocs": [{ "category": "url", "value": "http://xor-c2.example.net/beacon?id=1337" }] }
  ],
  "iocs": [{ "category": "url", "value": "http://evil-c2.example.com/gate.php" }],
  "is_interesting": true
}
```

### Options

| Flag | Meaning |
| --- | --- |
| `--json` | Emit a JSON report instead of tables |
| `--min-str N` | Minimum length for extracted/recovered strings (default: 4) |
| `--xor-max-keylen K` | Brute-force XOR keys up to K bytes; `0` disables the XOR pass (default: 1) |
| `--max-bytes N` | Refuse files larger than N bytes (default: 64 MiB) |
| `--fail-on-ioc` | Exit `1` when any IOC is recovered |
| `--version` | Print version |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysed successfully |
| `1` | Error (unreadable/oversized file), or IOCs found with `--fail-on-ioc` |
| `2` | Usage error |

## How it works

Strings are extracted as ASCII and UTF-16LE runs. Each string is run through the
token decoders: base64 and hex are surfaced whenever they decode to readable
text; ROT13 / Caesar and reversal are surfaced only when the transform reveals an
indicator, so the output stays signal rather than every rotation of every token.

Single-byte XOR is brute-forced exhaustively with `bytes.translate` tables; short
repeating keys are recovered per column by scoring each candidate for
English-likeness. A key is reported only when un-masking reveals a strong
indicator (URL, IP, path, registry key, email), which a random byte stream will
not produce. Stacked-string reconstruction walks the buffer at strides 2–4 and
keeps a run only when it spells out such an indicator.

Reads are bounded (64 MiB by default) so a crafted file cannot exhaust memory.

## Roadmap

- Emulated stack-string recovery (register/stack tracking) for non-IOC strings
- Longer repeating-key XOR with key-schedule scoring
- Layered transforms (base64 → gzip/zlib, base32)
- Per-candidate confidence scores and configurable TLD / IOC rule sets

## Authorized use

strdeob performs **static analysis only**: it reads a file and never executes it
or makes network calls. Analyse only files you are authorized to handle, and run
untrusted samples in an isolated environment. The test fixtures in this
repository are harmless and generated in code — no real malware is included.

## License

MIT — see [LICENSE](LICENSE).
