# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Opt-in probing of 10 common DKIM selectors (`--probe-dkim`, `probe_dkim` in the API, UI
  checkbox). Only existing keys are reported; DKIM-008 when none is found.
- IPv6 (AAAA) addresses of the authoritative name servers are now queried too (up to 2 IPv4
  and 2 IPv6 per server). IPv6 network errors are shown as not checked, not as DNS-007.
- SPF void lookup limit (RFC 7208 section 4.6.4): more than 2 `a`, `mx`, `exists`, `include`
  or `redirect` lookups returning NXDOMAIN or an empty answer raise SPF-014 and mark the
  record invalid.
- BIMI record check (`default._bimi`): syntax, certificate presence and whether DMARC is
  enforced enough for the logo to be shown (BIMI-001 to BIMI-004). New dashboard card,
  PDF row and CLI line.

## [0.2.0] - 2026-11-22

### Added
- Full DNSSEC chain validation from the root trust anchors (root -> TLD -> domain), with
  a new DNSSEC-008 finding when the chain does not validate.
- MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) record checks for domains that receive mail,
  with a new dashboard card, PDF row and CLI line (MTASTS-001/002, TLSRPT-001/002).
- Authoritative name server checks: each NS is queried directly for the SOA to detect
  lame delegations (DNS-006), unresponsive servers (DNS-007) and SOA serial mismatches
  (DNS-008). Shown in the dashboard, PDF report and history comparison.
- DMARC fallback now uses the Public Suffix List (`publicsuffix2`), so `mail.example.co.uk`
  falls back to `example.co.uk` instead of `co.uk`.
- Command line mode: `dnsinspector check <domain>` with `--selector`, `--json` and
  `--fail-on` (exit code 1 when findings reach that severity), for scripts and CI.

## [0.1.0] - 2026-11-16

### Added
- DNS lookup engine for A, AAAA, MX, CNAME, TXT, NS, SOA and PTR with TTL, resolver,
  response time and `ok` / `nodata` / `nxdomain` / `timeout` / `error` classification.
- SPF audit: syntax validation, duplicates, permissive `all`, deprecated `ptr`, recursive
  10-lookup limit with loop detection.
- DKIM key record audit for user-provided selectors, with exact RSA key size.
- DMARC audit: tag parsing and validation, weak policy detection, subdomain fallback.
- DNSSEC audit: DS/DNSKEY detection, local DS -> DNSKEY and DNSKEY RRSIG verification,
  AD flag reporting, deprecated algorithm and SHA-1 DS checks.
- Findings engine with documented severity rules and catalog (`docs/FINDINGS.md`).
- REST API with input validation, per-IP rate limiting and security headers.
- SQLite analysis history with listing, deletion and comparison of two analyses.
- JSON and PDF report export.
- Dark, responsive web dashboard with Analyze, Lookup and History views.
- Docker image (non-root, health check), Docker Compose and GitHub Actions CI.

### Fixed
- A DNS failure while resolving a nested SPF include was reported as a broken include
  (High); it is now an informational finding (SPF-013).
