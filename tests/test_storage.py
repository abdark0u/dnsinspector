import pytest

from dnsinspector.analyzer import analyze
from dnsinspector.compare import compare_reports
from dnsinspector.dns_engine import DnsEngine
from dnsinspector.storage import Storage
from tests.fakes import FakeResolver
from tests.test_analyzer import GOOD_ZONE


def report_for(data, domain="example.com"):
    return analyze(DnsEngine(resolver=FakeResolver(data)), domain)


@pytest.fixture
def storage(tmp_path):
    return Storage(tmp_path / "sub" / "test.db")


def test_save_get_list_delete(storage):
    report = report_for(GOOD_ZONE)
    first = storage.save(report)
    second = storage.save(report)
    assert storage.get(first)["domain"] == "example.com"
    assert storage.get(first)["id"] == first
    items = storage.list()
    assert [i["id"] for i in items] == [second, first]
    assert items[0]["counts"]["low"] == 2
    assert storage.list(domain="other.com") == []
    assert storage.delete(first) is True
    assert storage.delete(first) is False
    assert storage.get(first) is None


def test_list_limit(storage):
    report = report_for(GOOD_ZONE)
    for _ in range(5):
        storage.save(report)
    assert len(storage.list(limit=2)) == 2
    assert len(storage.list(limit=2, offset=4)) == 1


def test_compare_detects_changes(storage):
    before = report_for(GOOD_ZONE)
    changed = {**GOOD_ZONE, ("example.com", "A"): ["192.0.2.2"]}
    changed.pop(("_dmarc.example.com", "TXT"))
    after = report_for(changed)
    a, b = storage.save(before), storage.save(after)

    diff = compare_reports(storage.get(b), storage.get(a))  # el orden da igual
    assert diff["before"]["id"] == a
    assert diff["records"]["A"] == {
        "added": ["192.0.2.2"],
        "removed": ["192.0.2.1"],
        "unchanged": [],
    }
    assert diff["statuses"]["dmarc"] == {"before": "ok", "after": "missing", "changed": True}
    assert [f["id"] for f in diff["findings"]["new"]] == ["DMARC-001"]
    assert diff["findings"]["resolved"] == []


def test_compare_rejects_different_domains():
    with pytest.raises(ValueError):
        compare_reports(report_for(GOOD_ZONE), {**report_for(GOOD_ZONE), "domain": "other.com"})
