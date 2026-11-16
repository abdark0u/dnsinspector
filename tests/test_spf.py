import dns.exception

from dnsinspector.audits.spf import audit_spf, find_spf_records, parse_spf
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver


def run(data, domain="example.com"):
    return audit_spf(DnsEngine(resolver=FakeResolver(data)), domain)


def ids(findings):
    return {f.id for f in findings}


def test_find_spf_ignores_other_txt():
    assert find_spf_records(["google-site-verification=x", "v=spf1 -all", "v=spf10"]) == [
        "v=spf1 -all"
    ]


def test_parse_valid_record():
    terms, errors = parse_spf("v=spf1 ip4:192.0.2.0/24 include:_spf.x.com mx -all")
    assert errors == []
    assert [t["name"] for t in terms] == ["ip4", "include", "mx", "all"]
    assert terms[-1]["qualifier"] == "-"


def test_parse_syntax_errors():
    _, errors = parse_spf("v=spf1 ip4:999.1.1.1 ip6:192.0.2.1 inclde:x.com include: -all")
    assert len(errors) == 4


def test_good_record_is_ok():
    status, findings = run({("example.com", "TXT"): ['"v=spf1 ip4:192.0.2.1 -all"']})
    assert status["status"] == "ok"
    assert status["all"] == "-all"
    assert status["lookup_count"] == 0
    assert findings == []


def test_missing_spf():
    status, findings = run({("example.com", "TXT"): ['"hello"']})
    assert status["status"] == "missing"
    assert ids(findings) == {"SPF-001"}


def test_multiple_spf_records():
    status, findings = run({("example.com", "TXT"): ['"v=spf1 -all"', '"v=spf1 mx -all"']})
    assert status["status"] == "invalid"
    assert ids(findings) == {"SPF-002"}


def test_plus_all_is_critical():
    _, findings = run({("example.com", "TXT"): ['"v=spf1 +all"']})
    assert findings[0].id == "SPF-004"
    assert findings[0].severity == "critical"


def test_neutral_softfail_and_missing_all():
    assert "SPF-005" in ids(run({("example.com", "TXT"): ['"v=spf1 mx ?all"']})[1])
    assert "SPF-006" in ids(run({("example.com", "TXT"): ['"v=spf1 mx ~all"']})[1])
    assert "SPF-007" in ids(run({("example.com", "TXT"): ['"v=spf1 mx"']})[1])


def test_ptr_and_terms_after_all():
    _, findings = run({("example.com", "TXT"): ['"v=spf1 ptr -all mx"']})
    assert {"SPF-009", "SPF-012"} <= ids(findings)


def test_lookup_limit_exceeded():
    data = {("example.com", "TXT"): ['"v=spf1 include:a.com include:b.com -all"']}
    data[("a.com", "TXT")] = ['"v=spf1 ' + " ".join(f"a:h{i}.a.com" for i in range(6)) + ' -all"']
    data[("b.com", "TXT")] = ['"v=spf1 mx a ptr exists:x.b.com -all"']
    status, findings = run(data)
    assert status["status"] == "invalid"
    assert status["lookup_count"] > 10
    assert "SPF-008" in ids(findings)


def test_near_limit_warning():
    data = {("example.com", "TXT"): ['"v=spf1 include:a.com -all"']}
    data[("a.com", "TXT")] = ['"v=spf1 ' + " ".join(f"a:h{i}.a.com" for i in range(7)) + ' -all"']
    status, findings = run(data)
    assert status["lookup_count"] == 8
    assert "SPF-010" in ids(findings)


def test_include_without_spf_and_loops():
    data = {
        ("example.com", "TXT"): ['"v=spf1 include:nospf.com include:loop.com -all"'],
        ("nospf.com", "TXT"): ['"nothing"'],
        ("loop.com", "TXT"): ['"v=spf1 include:example.com -all"'],
    }
    status, findings = run(data)
    assert "SPF-011" in ids(findings)
    assert status["status"] == "invalid"


def test_dns_error_is_reported_not_guessed():
    status, findings = run({("example.com", "TXT"): dns.exception.Timeout})
    assert status["status"] == "error"
    assert ids(findings) == {"SPF-000"}
