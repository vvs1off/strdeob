# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Printable string extraction (ASCII and UTF-16LE).
- Per-string decoders: base64, hex, ROT13 / Caesar and reversal.
- Single-byte XOR brute force and short repeating-key recovery.
- Fixed-stride stacked-string reconstruction.
- IOC extraction (URL, email, IPv4, domain, Windows/Unix path, registry key)
  aggregated and deduplicated across every recovered candidate.
- Human-readable table output and `--json`.
- `--fail-on-ioc`, `--min-str`, `--xor-max-keylen`, `--max-bytes` and documented
  exit codes.
