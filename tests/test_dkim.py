import base64

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from dnsinspector.audits.dkim import audit_dkim, check_key_record
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

NAME = "s1._domainkey.example.com"


def rsa_p(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    return base64.b64encode(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def txt(record):
    # los TXT de mas de 255 caracteres van troceados
    chunks = [record[i : i + 250] for i in range(0, len(record), 250)]
    return " ".join(f'"{c}"' for c in chunks)


def run(record=None, selectors=("s1",)):
    data = {("example.com", "A"): ["192.0.2.1"]}
    if record is not None:
        data[(NAME, "TXT")] = [txt(record)]
    return audit_dkim(DnsEngine(resolver=FakeResolver(data)), "example.com", list(selectors))


def test_no_selector_is_not_checked():
    status, findings = run(selectors=())
    assert status["status"] == "not_checked"
    assert findings[0].id == "DKIM-001"


def test_rsa_2048_ok():
    status, findings = run(f"v=DKIM1; k=rsa; p={rsa_p(2048).decode()}")
    assert status["status"] == "ok"
    assert status["selectors"][0]["key_bits"] == 2048
    assert findings == []


def test_rsa_1024_low():
    status, findings = run(f"v=DKIM1; p={rsa_p(1024).decode()}")
    assert status["selectors"][0]["key_bits"] == 1024
    assert [f.id for f in findings] == ["DKIM-006"]


def test_ed25519_key():
    raw = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    status, _ = run(f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}")
    assert status["status"] == "ok"
    assert status["selectors"][0]["key_type"] == "ed25519"


def test_missing_selector_record():
    status, findings = run(None)
    assert status["status"] == "missing"
    assert findings[0].id == "DKIM-002"


def test_revoked_key():
    status, findings = run("v=DKIM1; p=")
    assert status["status"] == "revoked"
    assert findings[0].id == "DKIM-004"


def test_invalid_key_and_test_mode():
    status, findings = run("v=DKIM1; t=y; p=not-base64!!")
    assert status["status"] == "invalid"
    assert findings[0].id == "DKIM-003"
    assert check_key_record("k=dsa; p=AAAA")["errors"]
    assert check_key_record("k=rsa")["errors"] == ["Missing required public key tag 'p'"]
    assert check_key_record("p=AAAA; v=DKIM1")["errors"]


def test_test_mode_flag():
    _, findings = run(f"v=DKIM1; t=y; p={rsa_p(2048).decode()}")
    assert [f.id for f in findings] == ["DKIM-007"]


def test_probe_reports_only_existing_selectors():
    data = {("example.com", "A"): ["192.0.2.1"]}
    data[("google._domainkey.example.com", "TXT")] = [
        txt("v=DKIM1; k=rsa; p=" + rsa_p(2048).decode())
    ]
    resolver = FakeResolver(data)
    status, findings = audit_dkim(DnsEngine(resolver=resolver), "example.com", [], probe=True)
    assert [s["selector"] for s in status["selectors"]] == ["google"]
    assert status["selectors"][0]["probed"] is True
    assert findings == []
    probes = [c for c in resolver.calls if "_domainkey" in c[0]]
    assert len(probes) == 10


def test_probe_nothing_found_and_no_duplicate_queries():
    resolver = FakeResolver({("example.com", "A"): ["192.0.2.1"]})
    status, findings = audit_dkim(
        DnsEngine(resolver=resolver), "example.com", ["google"], probe=True
    )
    # google lo pidio el usuario: da DKIM-002 y no se prueba otra vez
    assert [f.id for f in findings] == ["DKIM-002"]
    assert len([c for c in resolver.calls if c[0].startswith("google._domainkey")]) == 1
    status, findings = audit_dkim(DnsEngine(resolver=resolver), "example.com", [], probe=True)
    assert status["status"] == "not_found"
    assert [f.id for f in findings] == ["DKIM-008"]
