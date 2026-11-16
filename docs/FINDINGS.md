# Findings catalog

Every problem DNSInspector reports is a *finding* with an ID, severity, title,
description, technical evidence, recommendation, category and (when applicable)
a reference to the relevant RFC.

There is **no numeric score**. The report shows the number of findings per
severity and the highest severity found. Severities follow the fixed rules below,
so the same configuration always gets the same result.

## Severity rules

| Severity | Rule |
|---|---|
| Critical | The configuration actively authorizes anyone to impersonate the domain. |
| High | A protection is missing or broken in a way receivers/resolvers will act on (permerror, ignored record, DNSSEC validation failure, unusable key). |
| Medium | A protection exists but is weak enough that spoofing or failure is still likely. |
| Low | Hygiene issue or best-practice gap with limited direct impact. |
| Info | Observation, or a check that could not be run. Not a problem by itself. |

## Catalog

| ID | Severity | Title |
|---|---|---|
| DNS-000 | Info | Domain does not exist (NXDOMAIN) |
| DNS-001 | Medium | Some DNS queries failed (timeout/SERVFAIL) |
| DNS-002 | Low | Only one name server |
| DNS-003 | Info | Domain does not accept mail (null MX) |
| DNS-004 | Info | No MX records |
| DNS-005 | Info | No IPv6 address (AAAA) |
| SPF-000 | Info | SPF could not be checked |
| SPF-001 | Medium | No SPF record |
| SPF-002 | High | Multiple SPF records (permerror) |
| SPF-003 | High | SPF syntax errors (permerror) |
| SPF-004 | Critical | SPF allows any server (`+all`) |
| SPF-005 | Medium | SPF ends in neutral `?all` |
| SPF-006 | Info | SPF ends in softfail `~all` |
| SPF-007 | Medium | SPF has no `all` mechanism and no `redirect` |
| SPF-008 | High | More than 10 DNS lookups (permerror) |
| SPF-009 | Low | Deprecated `ptr` mechanism |
| SPF-010 | Low | 8-10 lookups used (close to the limit) |
| SPF-011 | High | Broken include/redirect target or include loop |
| SPF-012 | Low | Terms after `all` are ignored |
| DKIM-001 | Info | DKIM not checked (no selector given) |
| DKIM-002 | Medium | No key record for the selector |
| DKIM-003 | High | Invalid key record (missing `p`, bad base64, bad `k`/`v`) |
| DKIM-004 | Info | Key revoked (empty `p=`) |
| DKIM-005 | High | RSA key under 1024 bits |
| DKIM-006 | Low | RSA key under 2048 bits |
| DKIM-007 | Low | Selector in test mode (`t=y`) |
| DMARC-000 | Info | DMARC could not be checked |
| DMARC-001 | High | No DMARC record |
| DMARC-002 | High | Multiple DMARC records |
| DMARC-003 | High | DMARC syntax errors |
| DMARC-004 | Medium | Policy `p=none` |
| DMARC-005 | Medium | Subdomain policy `sp=none` while `p` is enforced |
| DMARC-006 | Low | `pct` under 100 |
| DMARC-007 | Low | No aggregate report address (`rua`) |
| DMARC-008 | Low | Report URI is not `mailto:` |
| DMARC-009 | Info | Unknown DMARC tags |
| DNSSEC-000 | Info | DNSSEC could not be checked |
| DNSSEC-001 | Low | DNSSEC not enabled |
| DNSSEC-002 | Medium | Zone signed but no DS at the parent |
| DNSSEC-003 | High | Chain of trust broken (DS/DNSKEY mismatch, bad RRSIG, DS without DNSKEY) |
| DNSSEC-005 | Medium | Deprecated signing algorithm (RFC 8624) |
| DNSSEC-006 | Low | Only SHA-1 DS digests |
| DNSSEC-007 | Info | Resolver did not set the AD flag |

## What the statuses mean

| Check | Statuses |
|---|---|
| SPF | `ok`, `weak`, `invalid`, `missing`, `error`, `skipped` |
| DKIM | `ok`, `weak`, `invalid`, `missing`, `revoked`, `not_checked`, `error`, `skipped` |
| DMARC | `ok`, `weak`, `invalid`, `missing`, `error`, `skipped` |
| DNSSEC | `signed`, `unsigned`, `no_chain`, `broken`, `error`, `skipped` |

`signed` means DNSInspector verified locally that a DS record matches a DNSKEY and
that the DNSKEY RRset signature is valid. It is **not** a full validation of the
chain of trust from the root; see the README limitations section.
