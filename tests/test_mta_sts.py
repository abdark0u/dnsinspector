from dnsinspector.audits.mta_sts import audit_mta_sts, parse_mta_sts, parse_tls_rpt
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

STS = ("_mta-sts.example.com", "TXT")
RPT = ("_smtp._tls.example.com", "TXT")


def run(extra, mx=("10 mx.example.com.",)):
    data = {("example.com", "A"): ["192.0.2.1"], **extra}
    if mx:
        data[("example.com", "MX")] = list(mx)
    engine = DnsEngine(resolver=FakeResolver(data))
    return audit_mta_sts(engine, "example.com", engine.query("example.com", "MX"))


def ids(findings):
    return {f.id: f.severity.value for f in findings}


def test_both_records_ok():
    status, findings = run(
        {STS: ['"v=STSv1; id=20261120"'], RPT: ['"v=TLSRPTv1; rua=mailto:tls@example.com"']}
    )
    assert status["status"] == "ok"
    assert status["mta_sts"]["tags"]["id"] == "20261120"
    assert status["tls_rpt"]["status"] == "ok"
    assert findings == []


def test_nothing_published():
    status, findings = run({})
    assert status["status"] == "missing"
    assert ids(findings) == {"MTASTS-001": "low", "TLSRPT-001": "info"}


def test_sts_without_tls_rpt_is_low():
    _, findings = run({STS: ['"v=STSv1; id=1"']})
    assert ids(findings) == {"TLSRPT-001": "low"}


def test_invalid_records():
    status, findings = run({STS: ['"v=STSv1; id=bad-id!"'], RPT: ['"v=TLSRPTv1; rua=ftp://x"']})
    assert status["status"] == "invalid"
    assert set(ids(findings)) == {"MTASTS-002", "TLSRPT-002"}


def test_duplicate_sts_records():
    status, findings = run({STS: ['"v=STSv1; id=1"', '"v=STSv1; id=2"']})
    assert status["mta_sts"]["status"] == "invalid"
    assert "MTASTS-002" in ids(findings)


def test_not_applicable_without_mx():
    assert run({}, mx=None)[0]["status"] == "not_applicable"
    assert run({}, mx=("0 .",))[0]["status"] == "not_applicable"


def test_parsers():
    assert parse_mta_sts("v=STSv1;")[1] == ["Missing required tag 'id'"]
    assert parse_mta_sts("id=1; v=STSv1")[1] == ["Record must start with 'v=STSv1'"]
    assert parse_tls_rpt("v=TLSRPTv1; rua=https://r.example.com/x, mailto:a@b.c")[1] == []
    assert parse_tls_rpt("v=TLSRPTv1")[1] == ["Missing required tag 'rua'"]
