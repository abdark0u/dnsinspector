import json

import dns.exception

from dnsinspector.analyzer import analyze
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

GOOD_ZONE = {
    ("example.com", "A"): ["192.0.2.1"],
    ("example.com", "AAAA"): ["2001:db8::1"],
    ("example.com", "MX"): ["10 mx.example.com."],
    ("example.com", "NS"): ["ns1.example.com.", "ns2.example.net."],
    ("example.com", "SOA"): ["ns1.example.com. admin.example.com. 1 7200 3600 1209600 300"],
    ("example.com", "TXT"): ['"v=spf1 mx -all"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:d@example.com"'],
    # IPs de documentacion: no son publicas, asi que no se les manda nada
    ("ns1.example.com", "A"): ["192.0.2.53"],
    ("ns2.example.net", "A"): ["198.51.100.53"],
}


def ids(report):
    return [f["id"] for f in report["findings"]]


def run(data, selectors=None):
    return analyze(DnsEngine(resolver=FakeResolver(data)), "example.com", selectors)


def test_full_report_structure():
    report = run(GOOD_ZONE)
    json.dumps(report)  # tiene que ser serializable
    assert report["domain"] == "example.com"
    assert report["records"]["MX"]["records"] == ["10 mx.example.com."]
    assert report["records"]["CNAME"]["status"] == "nodata"
    assert report["spf"]["status"] == "ok"
    assert report["dmarc"]["status"] == "ok"
    assert report["dkim"]["status"] == "not_checked"
    assert report["dnssec"]["status"] == "unsigned"
    assert report["nameservers"]["status"] == "not_checked"
    assert ids(report) == ["DNSSEC-001", "MTASTS-001", "BIMI-001", "DKIM-001", "TLSRPT-001"]
    assert report["mta_sts"]["status"] == "missing"
    assert report["summary"]["highest_severity"] == "low"
    assert report["duration_ms"] >= 0


def test_findings_sorted_by_severity():
    data = {**GOOD_ZONE, ("example.com", "TXT"): ['"v=spf1 +all"']}
    data.pop(("_dmarc.example.com", "TXT"))
    report = run(data)
    severities = [f["severity"] for f in report["findings"]]
    assert severities[:2] == ["critical", "high"]
    assert report["summary"]["counts"]["critical"] == 1


def test_nxdomain_skips_audits():
    report = run({})
    assert ids(report) == ["DNS-000"]
    assert report["spf"]["status"] == "skipped"


def test_record_checks():
    data = {
        ("example.com", "A"): ["192.0.2.1"],
        ("example.com", "NS"): ["ns1.example.com."],
        ("example.com", "MX"): ["0 ."],
        ("example.com", "SOA"): dns.exception.Timeout,
    }
    found = set(ids(run(data)))
    assert {"DNS-001", "DNS-002", "DNS-003", "DNS-005"} <= found


def test_no_mx_and_selector_limit():
    data = {k: v for k, v in GOOD_ZONE.items() if k[1] != "MX"}
    report = run(data, selectors=[f"s{i}" for i in range(10)])
    assert "DNS-004" in ids(report)
    assert len(report["dkim"]["selectors"]) == 5
