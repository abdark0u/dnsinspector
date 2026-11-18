import dns.resolver

from dnsinspector.audits.dmarc import audit_dmarc, parse_dmarc
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

RUA = "rua=mailto:dmarc@example.com"


def run(record, domain="example.com", extra=None):
    data = {(domain, "A"): ["192.0.2.1"], **(extra or {})}
    if record is not None:
        data[(f"_dmarc.{domain}", "TXT")] = [f'"{record}"']
    return audit_dmarc(DnsEngine(resolver=FakeResolver(data)), domain)


def ids(findings):
    return {f.id for f in findings}


def test_reject_policy_ok():
    status, findings = run(f"v=DMARC1; p=reject; {RUA}; adkim=s; aspf=s")
    assert status["status"] == "ok"
    assert status["policy"] == "reject"
    assert status["tags"]["adkim"] == "s"
    assert findings == []


def test_missing_dmarc_is_high():
    status, findings = run(None)
    assert status["status"] == "missing"
    assert findings[0].id == "DMARC-001"
    assert findings[0].severity == "high"


def test_policy_none_is_weak():
    status, findings = run(f"v=DMARC1; p=none; {RUA}")
    assert status["status"] == "weak"
    assert ids(findings) == {"DMARC-004"}


def test_quarantine_with_weak_options():
    status, findings = run("v=DMARC1; p=quarantine; sp=none; pct=50; rua=https://x.com; foo=1")
    assert status["status"] == "weak"
    assert ids(findings) == {"DMARC-005", "DMARC-006", "DMARC-008", "DMARC-009"}


def test_no_rua_is_low():
    _, findings = run("v=DMARC1; p=reject")
    assert ids(findings) == {"DMARC-007"}


def test_syntax_errors():
    assert parse_dmarc("v=DMARC1; p=block")[1] == ["Invalid policy p=block"]
    assert parse_dmarc("p=reject; v=DMARC1")[1]
    assert parse_dmarc("v=DMARC1; p=reject; pct=150; adkim=x")[1] == [
        "adkim must be 'r' or 's'",
        "pct must be an integer between 0 and 100",
    ]
    status, findings = run("v=DMARC1; rua=mailto:a@b.com")
    assert status["status"] == "invalid"
    assert ids(findings) == {"DMARC-003"}


def test_multiple_records():
    data = {
        ("example.com", "A"): ["192.0.2.1"],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"'],
    }
    status, findings = audit_dmarc(DnsEngine(resolver=FakeResolver(data)), "example.com")
    assert status["status"] == "invalid"
    assert ids(findings) == {"DMARC-002"}


def test_subdomain_inherits_org_policy():
    extra = {("_dmarc.example.com", "TXT"): [f'"v=DMARC1; p=reject; {RUA}"']}
    status, findings = run(None, domain="mail.example.com", extra=extra)
    assert status["inherited"] is True
    assert status["source"] == "_dmarc.example.com"
    assert findings == []


def test_dns_failure_is_not_reported_as_missing():
    data = {("_dmarc.example.com", "TXT"): dns.resolver.NoNameservers}
    status, findings = audit_dmarc(DnsEngine(resolver=FakeResolver(data)), "example.com")
    assert status["status"] == "error"
    assert ids(findings) == {"DMARC-000"}


def test_org_domain_uses_public_suffix_list():
    # con la PSL, example.co.uk es el dominio organizativo (no co.uk)
    extra = {("_dmarc.example.co.uk", "TXT"): [f'"v=DMARC1; p=reject; {RUA}"']}
    status, findings = run(None, domain="mail.example.co.uk", extra=extra)
    assert status["inherited"] is True
    assert status["source"] == "_dmarc.example.co.uk"
    assert findings == []


def test_two_label_fallback_still_works():
    extra = {("_dmarc.example.com", "TXT"): [f'"v=DMARC1; p=reject; {RUA}"']}
    status, _ = run(None, domain="a.b.example.com", extra=extra)
    assert status["source"] == "_dmarc.example.com"
