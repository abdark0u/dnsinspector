import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from dnsinspector.audits.nameservers import audit_nameservers
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

NS = {
    ("example.com", "NS"): ["a.ns.test.", "b.ns.test."],
    ("a.ns.test", "A"): ["8.8.4.4"],
    ("b.ns.test", "A"): ["9.9.9.9"],
}


def fake_send(behaviour):
    """Simula servidores: ip -> serial, 'lame', 'refused' o una excepcion."""

    def send(query, ip, timeout):
        assert not query.flags & dns.flags.RD  # sin recursion
        value = behaviour[ip]
        if isinstance(value, Exception):
            raise value
        response = dns.message.make_response(query)
        if value == "refused":
            response.set_rcode(dns.rcode.REFUSED)
            return response
        if value != "lame":
            response.flags |= dns.flags.AA
            primary, serial = value if isinstance(value, tuple) else ("a.ns.test.", value)
            soa = f"{primary} admin.example.com. {serial} 7200 3600 1209600 300"
            response.answer.append(dns.rrset.from_text("example.com.", 300, "IN", "SOA", soa))
        return response

    return send


def run(behaviour, data=NS):
    engine = DnsEngine(resolver=FakeResolver(data), send=fake_send(behaviour))
    return audit_nameservers(engine, "example.com", engine.query("example.com", "NS"))


def ids(findings):
    return {f.id for f in findings}


def test_all_servers_ok():
    status, findings = run({"8.8.4.4": 2026111901, "9.9.9.9": 2026111901})
    assert status["status"] == "ok"
    assert [s["serial"] for s in status["servers"]] == [2026111901, 2026111901]
    assert findings == []


def test_serial_mismatch():
    status, findings = run({"8.8.4.4": 5, "9.9.9.9": 4})
    assert status["status"] == "inconsistent"
    assert ids(findings) == {"DNS-008"}


def test_lame_and_refused():
    status, findings = run({"8.8.4.4": "lame", "9.9.9.9": "refused"})
    assert status["status"] == "lame"
    assert ids(findings) == {"DNS-006"}
    assert "rcode REFUSED" in findings[0].evidence


def test_timeout():
    status, findings = run({"8.8.4.4": 1, "9.9.9.9": dns.exception.Timeout()})
    assert status["status"] == "unreachable"
    assert ids(findings) == {"DNS-007"}


def test_unresolved_ns_name():
    data = {k: v for k, v in NS.items() if k[0] != "b.ns.test"}
    status, findings = run({"8.8.4.4": 1}, data)
    assert status["servers"][1]["status"] == "unresolved"
    assert ids(findings) == {"DNS-006"}


def test_private_ns_address_is_not_queried():
    data = {**NS, ("a.ns.test", "A"): ["10.0.0.1"], ("b.ns.test", "A"): ["192.168.1.1"]}
    status, findings = run({}, data)  # si se consultara, fake_send fallaria con KeyError
    assert status["status"] == "not_checked"
    assert findings == []


def test_no_ns_records():
    engine = DnsEngine(resolver=FakeResolver({("example.com", "A"): ["192.0.2.1"]}))
    status, _ = audit_nameservers(engine, "example.com", engine.query("example.com", "NS"))
    assert status["status"] == "skipped"


def test_different_providers_are_not_compared():
    status, findings = run({"8.8.4.4": ("a.ns.test.", 5), "9.9.9.9": ("ns.other.test.", 999)})
    assert status["status"] == "ok"
    assert findings == []


def test_ipv6_server_is_checked():
    data = {**NS, ("b.ns.test", "AAAA"): ["2001:4860:4860::8888"]}
    status, findings = run({"8.8.4.4": 7, "9.9.9.9": 7, "2001:4860:4860::8888": 7}, data)
    ips = [s["ip"] for s in status["servers"]]
    assert "2001:4860:4860::8888" in ips
    assert status["status"] == "ok"
    assert findings == []


def test_ipv6_only_server_and_private_ipv6_skipped():
    data = {
        ("example.com", "NS"): ["a.ns.test."],
        ("a.ns.test", "AAAA"): ["2001:4860:4860::8888", "fd00::1"],
    }
    status, _ = run({"2001:4860:4860::8888": 3}, data)
    assert [s["status"] for s in status["servers"]] == ["ok", "not_checked"]


def test_ipv6_network_error_is_not_a_finding():
    data = {**NS, ("a.ns.test", "AAAA"): ["2001:4860:4860::8888"]}
    behaviour = {"8.8.4.4": 7, "9.9.9.9": 7, "2001:4860:4860::8888": OSError("No route to host")}
    status, findings = run(behaviour, data)
    assert status["status"] == "ok"
    assert findings == []
