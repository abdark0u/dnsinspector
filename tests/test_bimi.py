from dnsinspector.audits.bimi import audit_bimi, dmarc_enforced, parse_bimi
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

BIMI = ("default._bimi.example.com", "TXT")
REJECT = {"status": "ok", "policy": "reject", "tags": {"p": "reject"}}
NONE = {"status": "weak", "policy": "none", "tags": {"p": "none"}}
GOOD = '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"'


def run(extra, dmarc=REJECT, mx=("10 mx.example.com.",)):
    data = {("example.com", "A"): ["192.0.2.1"], **extra}
    if mx:
        data[("example.com", "MX")] = list(mx)
    engine = DnsEngine(resolver=FakeResolver(data))
    return audit_bimi(engine, "example.com", engine.query("example.com", "MX"), dmarc)


def ids(findings):
    return [f.id for f in findings]


def test_valid_record_with_enforced_dmarc():
    status, findings = run({BIMI: [GOOD]})
    assert status["status"] == "ok"
    assert status["tags"]["l"] == "https://example.com/logo.svg"
    assert findings == []


def test_missing_only_reported_when_dmarc_ready():
    assert ids(run({})[1]) == ["BIMI-001"]
    status, findings = run({}, dmarc=NONE)
    assert status["status"] == "missing"
    assert findings == []


def test_bimi_without_enforced_dmarc():
    assert ids(run({BIMI: [GOOD]}, dmarc=NONE)[1]) == ["BIMI-003"]


def test_invalid_and_no_certificate():
    assert ids(run({BIMI: ['"v=BIMI1; l=http://example.com/logo.png"']})[1]) == ["BIMI-002"]
    assert ids(run({BIMI: ['"v=BIMI1; l=https://example.com/logo.svg"']})[1]) == ["BIMI-004"]


def test_not_applicable_without_mx():
    assert run({}, mx=None)[0]["status"] == "not_applicable"


def test_parser_and_dmarc_rules():
    assert parse_bimi("v=BIMI1; l=")[1] == []  # l vacio = declina mostrar logo, es valido
    assert parse_bimi("l=https://x/a.svg; v=BIMI1")[1]
    assert not dmarc_enforced({"status": "ok", "policy": "quarantine", "tags": {"pct": "50"}})
    assert not dmarc_enforced({"status": "ok", "policy": "reject", "tags": {"sp": "none"}})
    assert dmarc_enforced({"status": "weak", "policy": "quarantine", "tags": {}})
