import dns.dnssec
import dns.name
import dns.resolver
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ed25519

from dnsinspector.audits.dnssec import audit_dnssec
from dnsinspector.dns_engine import DnsEngine
from tests.fakes import FakeResolver

NAME = dns.name.from_text("example.com")


def signed_zone(tamper=False):
    """Crea un DNSKEY firmado de verdad y su DS, como en una zona real."""
    private = ed25519.Ed25519PrivateKey.generate()
    key = dns.dnssec.make_dnskey(private.public_key(), dns.dnssec.Algorithm.ED25519, flags=257)
    keyset = dns.rrset.from_rdata(NAME, 3600, key)
    sig = dns.rrset.from_rdata(
        NAME, 3600, dns.dnssec.sign(keyset, private, NAME, key, lifetime=3600)
    )
    ds = dns.dnssec.make_ds(NAME, key, "SHA256")
    if tamper:  # DS de otra clave distinta
        other = ed25519.Ed25519PrivateKey.generate().public_key()
        ds = dns.dnssec.make_ds(NAME, dns.dnssec.make_dnskey(other, 15, flags=257), "SHA256")
    return (keyset, [sig]), [ds.to_text()]


def run(data, ad=False):
    data = {("example.com", "A"): ["192.0.2.1"], **data}
    return audit_dnssec(DnsEngine(resolver=FakeResolver(data, ad=ad)), "example.com")


def ids(findings):
    return {f.id for f in findings}


def test_unsigned():
    status, findings = run({})
    assert status["status"] == "unsigned"
    assert ids(findings) == {"DNSSEC-001"}


def test_valid_chain_with_ad_flag():
    keys, ds = signed_zone()
    status, findings = run({("example.com", "DNSKEY"): keys, ("example.com", "DS"): ds}, ad=True)
    assert status["status"] == "signed"
    assert status["validation"]["ds_matches_dnskey"] is True
    assert status["validation"]["dnskey_signature_valid"] is True
    assert status["dnskey"][0]["role"] == "KSK"
    assert status["ad_flag"] is True
    assert findings == []


def test_valid_chain_without_ad_is_informational():
    keys, ds = signed_zone()
    status, findings = run({("example.com", "DNSKEY"): keys, ("example.com", "DS"): ds})
    assert status["status"] == "signed"
    assert ids(findings) == {"DNSSEC-007"}


def test_ds_mismatch_is_broken():
    keys, ds = signed_zone(tamper=True)
    status, findings = run({("example.com", "DNSKEY"): keys, ("example.com", "DS"): ds})
    assert status["status"] == "broken"
    assert "DNSSEC-003" in ids(findings)


def test_bad_signature_is_broken():
    (keyset, _), ds = signed_zone()
    (_, other_sigs), _ = signed_zone()
    status, _ = run({("example.com", "DNSKEY"): (keyset, other_sigs), ("example.com", "DS"): ds})
    assert status["status"] == "broken"
    assert any("RRSIG" in e for e in status["validation"]["errors"])


def test_dnskey_without_ds():
    keys, _ = signed_zone()
    status, findings = run({("example.com", "DNSKEY"): keys})
    assert status["status"] == "no_chain"
    assert ids(findings) == {"DNSSEC-002"}


def test_ds_without_dnskey_answer():
    _, ds = signed_zone()
    status, findings = run(
        {("example.com", "DS"): ds, ("example.com", "DNSKEY"): dns.resolver.NoNameservers}
    )
    assert status["status"] == "broken"
    assert ids(findings) == {"DNSSEC-003"}


def test_sha1_only_ds():
    keys, _ = signed_zone()
    sha1 = dns.dnssec.make_ds(NAME, keys[0][0], "SHA1", validating=True).to_text()
    status, findings = run(
        {("example.com", "DNSKEY"): keys, ("example.com", "DS"): [sha1]}, ad=True
    )
    assert status["status"] == "signed"
    assert ids(findings) == {"DNSSEC-006"}


# --- cadena de confianza raiz -> com -> example.com ---


def make_zone(name, parent_name=None, parent_priv=None, parent_key=None):
    """Zona con una clave que firma todo: devuelve DNSKEY firmado y el DS firmado por el padre."""
    zone = dns.name.from_text(name)
    private = ed25519.Ed25519PrivateKey.generate()
    key = dns.dnssec.make_dnskey(private.public_key(), dns.dnssec.Algorithm.ED25519, flags=257)
    keyset = dns.rrset.from_rdata(zone, 3600, key)
    sig = dns.rrset.from_rdata(
        zone, 3600, dns.dnssec.sign(keyset, private, zone, key, lifetime=3600)
    )
    ds_rr = None
    if parent_priv:
        ds = dns.dnssec.make_ds(zone, key, "SHA256")
        ds_set = dns.rrset.from_rdata(zone, 3600, ds)
        ds_sig = dns.rrset.from_rdata(
            zone,
            3600,
            dns.dnssec.sign(
                ds_set, parent_priv, dns.name.from_text(parent_name), parent_key, lifetime=3600
            ),
        )
        ds_rr = (ds_set, [ds_sig])
    return private, key, (keyset, [sig]), ds_rr


def hierarchy(break_com_ds=False):
    root_priv, root_key, root_keys, _ = make_zone(".")
    com_priv, com_key, com_keys, com_ds = make_zone("com", ".", root_priv, root_key)
    _, _, ex_keys, ex_ds = make_zone("example.com", "com", com_priv, com_key)
    if break_com_ds:  # DS de com firmado por otra clave que no es la de la raiz
        other_priv, other_key, _, _ = make_zone(".")
        _, _, _, com_ds = make_zone("com", ".", other_priv, other_key)
    anchor = dns.dnssec.make_ds(dns.name.root, root_key, "SHA256").to_text()
    data = {
        (".", "DNSKEY"): root_keys,
        ("com", "DS"): com_ds,
        ("com", "DNSKEY"): com_keys,
        ("example.com", "DS"): ex_ds,
        ("example.com", "DNSKEY"): ex_keys,
    }
    return data, anchor


def test_full_chain_valid():
    data, anchor = hierarchy()
    engine = DnsEngine(resolver=FakeResolver({("example.com", "A"): ["192.0.2.1"], **data}))
    status, findings = audit_dnssec(engine, "example.com", anchors=(anchor,))
    assert status["status"] == "signed"
    assert status["validation"]["chain"]["status"] == "valid"
    assert [s["zone"] for s in status["validation"]["chain"]["steps"]] == [
        ".",
        "com.",
        "example.com.",
    ]
    assert "DNSSEC-008" not in ids(findings)


def test_chain_broken_in_parent_ds():
    data, anchor = hierarchy(break_com_ds=True)
    engine = DnsEngine(resolver=FakeResolver({("example.com", "A"): ["192.0.2.1"], **data}))
    status, findings = audit_dnssec(engine, "example.com", anchors=(anchor,))
    assert status["status"] == "broken"
    assert "DNSSEC-008" in ids(findings)


def test_wrong_trust_anchor_is_invalid():
    data, _ = hierarchy()
    _, other_key, _, _ = make_zone(".")
    wrong = dns.dnssec.make_ds(dns.name.root, other_key, "SHA256").to_text()
    engine = DnsEngine(resolver=FakeResolver({("example.com", "A"): ["192.0.2.1"], **data}))
    status, findings = audit_dnssec(engine, "example.com", anchors=(wrong,))
    assert "DNSSEC-008" in ids(findings)


def test_chain_incomplete_does_not_add_finding():
    # sin datos de la raiz no se puede validar, pero tampoco es un fallo
    keys, ds = signed_zone()
    status, findings = run({("example.com", "DNSKEY"): keys, ("example.com", "DS"): ds}, ad=True)
    assert status["validation"]["chain"]["status"] == "incomplete"
    assert findings == []
