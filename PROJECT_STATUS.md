# Project status

_Last updated: 2026-11-22_

## Current phase

**Version 0.2.0 released.** Phases 1-10 of the original plan are complete. Next work is
the roadmap in the README (stages below).

All the work up to v0.1.0 was done in a single working session on 2026-11-16. The commit
history reflects that real order of work; no dates were changed.

## Completed

| Phase | Result | Verified by |
|---|---|---|
| 1. Research & architecture | `docs/ARCHITECTURE.md`, RFC references, decisions | review |
| 2. Core DNS engine | `dns_engine.py`, status classification | unit tests |
| 3. Security auditing | SPF, DKIM, DMARC, DNSSEC audits | unit tests + live checks (cloudflare.com, github.com, dnssec-failed.org) |
| 4. Findings engine | `findings.py`, `docs/FINDINGS.md` | unit tests |
| 5. Backend & database | REST API, SQLite history, comparison | API tests |
| 6. Frontend | Dashboard, lookup, history, compare (PR #1) | manual browser test, desktop + 375px mobile |
| 7. Reporting | JSON + PDF export | tests + visual check of the PDF |
| 8. Testing & security review | 112 tests, ruff (incl. bandit rules), pip-audit clean | CI |
| 9. Documentation & GitHub | README, CONTRIBUTING, SECURITY, CHANGELOG, screenshots | review |
| 10. Final verification | Fresh clone + install on Python 3.15, tests, live analysis, PDF | manual; Docker verified in CI (no local Docker on the dev machine) |

## Last commit before this file

`066bcc1 docs(project): add contributing guide, security policy and changelog` (run `git log -1` for the current one).

## Problems found and solved

- SPF: a timeout while resolving a nested include was reported as a broken include (High).
  Fixed: now SPF-013 (Info), lookup count marked as a lower bound.
- Frontend: forms submitted without a submit button reference threw an error. Fixed.
- Docker is not installed on the development machine, so the image is built and
  smoke-tested in GitHub Actions instead (build, health check, real analysis, PDF).

## Pending / known issues

- Limitations listed in the README (partial DNSSEC validation, in-memory rate limiter, no authentication, Latin-1 PDF fonts).
- Starlette warns that its test client will move from `httpx` to `httpx2`; harmless today.

## Next stages (plan, not done yet)

Each stage ends with tests passing, a CHANGELOG entry and a push.

| Stage | Goal | Verifiable result |
|---|---|---|
| 1 | Public Suffix List for DMARC org domain | **Done 2026-11-18**: `tests/test_dmarc.py` |
| 2 | Per-authoritative-server checks (SOA serial consistency, lame delegation) | **Done 2026-11-19**: `tests/test_nameservers.py`, DNS-006/007/008 |
| 3 | MTA-STS and TLS-RPT records | **Done 2026-11-20**: `tests/test_mta_sts.py`, dashboard card |
| 4 | Full DNSSEC chain validation from the root | **Done 2026-11-21**: `tests/test_dnssec.py` (signed root/com/example.com hierarchy), DNSSEC-008 |
| 5 | CLI mode (`dnsinspector check example.com --json`) | **Done 2026-11-17**: `tests/test_cli.py`, README section |
| 6 | Release v0.2.0 | **Done 2026-11-22**: tag, GitHub release, CI green |
| 7 | BIMI record check | **Done 2026-11-22**: `tests/test_bimi.py`, dashboard card (unreleased) |

## How to resume

1. Read this file and `git log --oneline | head -20`.
2. `git pull`, then `pip install -e ".[dev]"` and `pytest -q` to confirm a green start.
3. Check CI: `gh run list --limit 3`.
4. Continue with the first stage above that is not done.
