import dns.exception
import pytest
from fastapi.testclient import TestClient

from dnsinspector.api import create_app
from dnsinspector.config import Settings
from dnsinspector.dns_engine import DnsEngine
from dnsinspector.storage import Storage
from tests.fakes import FakeResolver
from tests.test_analyzer import GOOD_ZONE

ZONE = {**GOOD_ZONE, ("8.8.8.8.in-addr.arpa", "PTR"): ["dns.google."]}


def make_client(tmp_path, rate_limit=100, data=ZONE):
    settings = Settings(database_path=tmp_path / "api.db", rate_limit_per_minute=rate_limit)
    engine = DnsEngine(resolver=FakeResolver(data))
    app = create_app(settings, engine=engine, storage=Storage(settings.database_path))
    return TestClient(app)


@pytest.fixture
def client(tmp_path):
    return make_client(tmp_path)


def test_health_and_static(client):
    assert client.get("/api/health").json()["status"] == "ok"
    page = client.get("/")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in page.headers["content-security-policy"]


def test_lookup_all_types(client):
    data = client.get("/api/lookup", params={"name": "Example.com"}).json()
    assert data["query"] == "example.com"
    assert [r["rtype"] for r in data["results"]] == ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]
    assert data["results"][3]["status"] == "nodata"


def test_lookup_single_type_and_ptr(client):
    data = client.get("/api/lookup", params={"name": "example.com", "type": "mx"}).json()
    assert data["results"][0]["records"] == ["10 mx.example.com."]
    ptr = client.get("/api/lookup", params={"name": "8.8.8.8"}).json()
    assert ptr["kind"] == "ptr"
    assert ptr["results"][0]["records"] == ["dns.google."]


@pytest.mark.parametrize(
    "params",
    [{"name": "not a domain"}, {"name": "192.168.1.1"}, {"name": "example.com", "type": "AXFR"}],
)
def test_lookup_rejects_bad_input(client, params):
    response = client.get("/api/lookup", params=params)
    assert response.status_code == 422


def test_analysis_lifecycle(client):
    created = client.post("/api/analyses", json={"domain": "EXAMPLE.com", "dkim_selectors": []})
    assert created.status_code == 201
    analysis = created.json()
    analysis_id = analysis["id"]
    assert analysis["domain"] == "example.com"
    assert analysis["spf"]["status"] == "ok"

    history = client.get("/api/analyses").json()
    assert history[0]["id"] == analysis_id
    assert client.get("/api/analyses", params={"domain": "example.com"}).json()
    assert client.get(f"/api/analyses/{analysis_id}").json()["domain"] == "example.com"

    json_report = client.get(f"/api/analyses/{analysis_id}/report.json")
    assert json_report.json()["id"] == analysis_id
    assert "attachment" in json_report.headers["content-disposition"]
    pdf = client.get(f"/api/analyses/{analysis_id}/report.pdf")
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")
    assert client.get(f"/api/analyses/{analysis_id}/report.xml").status_code == 404

    assert client.delete(f"/api/analyses/{analysis_id}").status_code == 204
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
    assert client.delete(f"/api/analyses/{analysis_id}").status_code == 404


def test_analysis_validation(client):
    assert client.post("/api/analyses", json={"domain": "localhost"}).status_code == 422
    bad_selector = {"domain": "example.com", "dkim_selectors": ["bad;sel"]}
    assert client.post("/api/analyses", json=bad_selector).status_code == 422
    too_many = {"domain": "example.com", "dkim_selectors": [f"s{i}" for i in range(6)]}
    assert client.post("/api/analyses", json=too_many).status_code == 422


def test_selectors_are_deduplicated(client):
    body = {"domain": "example.com", "dkim_selectors": ["S1", "s1", " "]}
    data = client.post("/api/analyses", json=body).json()
    assert [s["selector"] for s in data["dkim"]["selectors"]] == ["s1"]


def test_compare_endpoint(client, tmp_path):
    a = client.post("/api/analyses", json={"domain": "example.com"}).json()["id"]
    b = client.post("/api/analyses", json={"domain": "example.com"}).json()["id"]
    diff = client.get("/api/compare", params={"a": a, "b": b}).json()
    assert diff["findings"]["new"] == []
    assert client.get("/api/compare", params={"a": a, "b": 999}).status_code == 404


def test_compare_different_domains(tmp_path):
    data = {**ZONE, ("other.com", "A"): ["192.0.2.9"]}
    client = make_client(tmp_path, data=data)
    a = client.post("/api/analyses", json={"domain": "example.com"}).json()["id"]
    b = client.post("/api/analyses", json={"domain": "other.com"}).json()["id"]
    assert client.get("/api/compare", params={"a": a, "b": b}).status_code == 422


def test_rate_limit(tmp_path):
    client = make_client(tmp_path, rate_limit=2)
    for _ in range(2):
        assert client.get("/api/lookup", params={"name": "example.com"}).status_code == 200
    blocked = client.get("/api/lookup", params={"name": "example.com"})
    assert blocked.status_code == 429
    assert client.get("/api/analyses").status_code == 200  # el historial no esta limitado


def test_timeout_is_returned_as_status(tmp_path):
    client = make_client(tmp_path, data={("slow.com", "A"): dns.exception.Timeout})
    data = client.get("/api/lookup", params={"name": "slow.com", "type": "A"}).json()
    assert data["results"][0]["status"] == "timeout"
