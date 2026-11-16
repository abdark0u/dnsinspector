# Contributing

Thanks for your interest in DNSInspector.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check .
ruff format --check .
pytest -q
```

- Tests must not depend on the Internet. Use `tests/fakes.py` (`FakeResolver`) to
  describe the DNS answers your test needs.
- New findings need a unique ID, a severity that follows the rules in
  [docs/FINDINGS.md](docs/FINDINGS.md), an RFC reference when one exists, an entry in
  that catalog and a test.
- Do not claim more than the code verifies (e.g. "DNSSEC valid" or "DKIM valid").
- Keep the tool non-intrusive: standard DNS queries through the configured resolver only.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) with a scope, e.g.
`feat(spf): ...`, `fix(api): ...`, `docs(readme): ...`. Keep commits small and focused,
and update `CHANGELOG.md` for user-visible changes.
