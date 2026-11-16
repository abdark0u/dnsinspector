import dns.exception
import dns.resolver

from dnsinspector.dns_engine import ERROR, NODATA, NXDOMAIN, OK, TIMEOUT, DnsEngine
from tests.fakes import FakeResolver


def make_engine(data, **kw):
    return DnsEngine(resolver=FakeResolver(data, **kw))


def test_record_found_with_ttl_and_nameserver():
    engine = make_engine({("example.com", "A"): ["93.184.215.14"]})
    result = engine.query("example.com", "A")
    assert result.status == OK
    assert result.records == ["93.184.215.14"]
    assert result.ttl == 300
    assert result.nameserver == "192.0.2.53"
    assert result.elapsed_ms >= 0


def test_mx_sorted_by_preference():
    engine = make_engine({("example.com", "MX"): ["20 mx2.example.com.", "10 mx1.example.com."]})
    assert engine.query("example.com", "MX").records == [
        "10 mx1.example.com.",
        "20 mx2.example.com.",
    ]


def test_long_txt_strings_are_joined():
    engine = make_engine({("example.com", "TXT"): ['"v=spf1 " "include:x.com -all"']})
    assert engine.query("example.com", "TXT").records == ["v=spf1 include:x.com -all"]


def test_nodata_when_name_exists_without_type():
    engine = make_engine({("example.com", "A"): ["192.0.2.1"]})
    result = engine.query("example.com", "AAAA")
    assert result.status == NODATA
    assert result.records == []


def test_nxdomain():
    result = make_engine({}).query("nope.example.com", "A")
    assert result.status == NXDOMAIN


def test_timeout():
    engine = make_engine({("slow.com", "A"): dns.exception.Timeout})
    result = engine.query("slow.com", "A")
    assert result.status == TIMEOUT
    assert "timed out" in result.error


def test_servfail_is_error():
    engine = make_engine({("broken.com", "A"): dns.resolver.NoNameservers})
    result = engine.query("broken.com", "A")
    assert result.status == ERROR
    assert result.error


def test_ad_flag_is_reported():
    engine = make_engine({("example.com", "A"): ["192.0.2.1"]}, ad=True)
    assert engine.query("example.com", "A").ad_flag is True


def test_ptr_lookup():
    engine = make_engine({("8.8.8.8.in-addr.arpa", "PTR"): ["dns.google."]})
    result = engine.reverse("8.8.8.8")
    assert result.status == OK
    assert result.name == "8.8.8.8"
    assert result.records == ["dns.google."]


def test_to_dict_drops_raw_data():
    data = make_engine({("example.com", "A"): ["192.0.2.1"]}).query("example.com", "A").to_dict()
    assert "rrset" not in data and "rrsigs" not in data
    assert data["status"] == OK
