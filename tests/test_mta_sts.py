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


# --- politica (fetcher falso, sin red) ---
from dnsinspector.audits.mta_sts import PolicyError, fetch_policy, mx_matches, parse_policy  # noqa: E402

GOOD = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"
HOST = ("mta-sts.example.com", "A")


def run_policy(fetcher, hosts=None):
    data = {("example.com", "A"): ["192.0.2.1"], ("example.com", "MX"): ["10 mx.example.com."]}
    data[STS] = ['"v=STSv1; id=1"']
    data[RPT] = ['"v=TLSRPTv1; rua=mailto:t@example.com"']
    data.update(hosts if hosts is not None else {HOST: ["203.0.113.5"]})
    engine = DnsEngine(resolver=FakeResolver(data))
    return audit_mta_sts(engine, "example.com", engine.query("example.com", "MX"), fetcher)


def test_policy_ok():
    status, findings = run_policy(lambda host, ips: GOOD)
    assert status["policy"]["status"] == "ok"
    assert findings == []


def test_policy_unreachable():
    def boom(host, ips):
        raise PolicyError("HTTP 404")

    status, findings = run_policy(boom)
    assert status["policy"]["status"] == "unreachable"
    assert ids(findings) == {"MTASTS-003": "medium"}


def test_policy_no_host_record():
    status, findings = run_policy(lambda h, i: GOOD, hosts={("mta-sts.example.com", "TXT"): ["x"]})
    assert "MTASTS-003" in ids(findings)


def test_policy_invalid():
    _, findings = run_policy(lambda h, i: "mode: maybe\n")
    assert ids(findings) == {"MTASTS-004": "medium"}


def test_policy_mx_not_covered():
    _, findings = run_policy(lambda h, i: GOOD.replace("mx.example.com", "other.example.net"))
    assert ids(findings) == {"MTASTS-005": "high"}


def test_policy_testing_and_short_max_age():
    text = "version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 60\n"
    _, findings = run_policy(lambda h, i: text)
    assert ids(findings) == {"MTASTS-006": "low", "MTASTS-007": "low"}


def test_wildcard_one_label():
    assert mx_matches("*.example.com", "mx.example.com.")
    assert not mx_matches("*.example.com", "a.b.example.com")
    assert not mx_matches("*.example.com", "example.com")


def test_parse_policy_errors():
    assert parse_policy(GOOD)[1] == []
    assert "max_age is above one year" in parse_policy(GOOD.replace("604800", "99999999"))[1]


def test_fetch_refuses_private_ips():
    try:
        fetch_policy("mta-sts.example.com", ["10.0.0.1", "127.0.0.1"])
    except PolicyError as exc:
        assert "no public address" in str(exc)
    else:
        raise AssertionError("expected PolicyError")
