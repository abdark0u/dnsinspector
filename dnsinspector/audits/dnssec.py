"""Auditoria DNSSEC.

Comprobamos: DS en el padre, DNSKEY en la zona, que algun DS coincida con una DNSKEY
y que la firma (RRSIG) del conjunto DNSKEY sea valida. Ademas validamos la cadena de
confianza desde la raiz (ancla de confianza -> TLD -> dominio).
"""

import secrets

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rrset

from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "DNSSEC"
NOTE = (
    "DNSInspector checks that the parent DS matches a DNSKEY, that the DNSKEY set is "
    "correctly signed and that the chain of trust validates from the IANA root trust "
    "anchors down to the domain. The AD flag is reported as returned by the resolver."
)
# anclas de confianza de la raiz (IANA, KSK-2017 y KSK-2024), en formato DS
ROOT_TRUST_ANCHORS = (
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)
# algoritmos que ya no se deben usar para firmar (RFC 8624)
DEPRECATED_ALGORITHMS = {1, 3, 5, 6, 7, 12}
ANSWERED = (OK, NODATA, NXDOMAIN)


def _key_info(rdata) -> dict:
    return {
        "key_tag": dns.dnssec.key_id(rdata),
        "algorithm": dns.dnssec.algorithm_to_text(rdata.algorithm),
        "algorithm_number": int(rdata.algorithm),
        "flags": rdata.flags,
        "role": "KSK" if rdata.flags & 0x0001 else "ZSK",
    }


def validate_locally(domain: str, ds: QueryResult, dnskey: QueryResult) -> dict:
    """Comprueba el enlace DS -> DNSKEY y la firma del DNSKEY con criptografia real."""
    name = dns.name.from_text(domain)
    result: dict = {"ds_matches_dnskey": False, "dnskey_signature_valid": False, "errors": []}
    for ds_rdata in ds.rrset:
        for key in dnskey.rrset:
            try:
                made = dns.dnssec.make_ds(name, key, ds_rdata.digest_type, validating=True)
            except (dns.dnssec.UnsupportedAlgorithm, ValueError):
                continue
            if made == ds_rdata:
                result["ds_matches_dnskey"] = True
                result["matched_key_tag"] = ds_rdata.key_tag
    if not result["ds_matches_dnskey"]:
        result["errors"].append("No DS record matches any published DNSKEY")

    if not dnskey.rrsigs:
        result["errors"].append("DNSKEY set has no RRSIG (resolver may not return DNSSEC data)")
        return result
    try:
        dns.dnssec.validate(dnskey.rrset, dnskey.rrsigs[0], {name: dnskey.rrset})
        result["dnskey_signature_valid"] = True
    except dns.dnssec.ValidationFailure as exc:
        result["errors"].append(f"DNSKEY RRSIG validation failed: {exc}")
    except dns.exception.DNSException as exc:
        result["errors"].append(f"Could not validate DNSKEY RRSIG: {exc}")
    return result


def _matching_keys(zone, ds_rdatas, dnskey_rrset):
    """Devuelve las DNSKEY de la zona que coinciden con algun DS."""
    matched = []
    for key in dnskey_rrset:
        for ds_rdata in ds_rdatas:
            try:
                made = dns.dnssec.make_ds(zone, key, ds_rdata.digest_type, validating=True)
            except (dns.dnssec.UnsupportedAlgorithm, ValueError):
                continue
            if made == ds_rdata:
                matched.append(key)
                break
    return matched


def _signed_by(signer, rrset, rrsigs, keys) -> bool:
    """True si alguna firma del rrset es valida con esas claves."""
    if not rrsigs or not keys:
        return False
    keyset = dns.rrset.from_rdata_list(signer, 0, keys)
    for sig in rrsigs:
        try:
            dns.dnssec.validate(rrset, sig, {signer: keyset})
            return True
        except (dns.dnssec.ValidationFailure, dns.exception.DNSException):
            continue
    return False


def validate_chain(engine: DnsEngine, domain: str, anchors=ROOT_TRUST_ANCHORS) -> dict:
    """Valida la cadena raiz -> TLD -> dominio. Estados: valid, invalid, incomplete."""
    result: dict = {"status": "valid", "steps": [], "error": None}
    labels = dns.name.from_text(domain).labels[:-1]
    zones = [dns.name.root] + [
        dns.name.Name(labels[i:] + (b"",)) for i in range(len(labels) - 1, -1, -1)
    ]

    def stop(status: str, message: str) -> dict:
        result["status"], result["error"] = status, message
        return result

    # raiz: el DS del ancla debe coincidir con una DNSKEY y esa clave firma el conjunto
    anchor_ds = [dns.rdata.from_text("IN", "DS", a) for a in anchors]
    keys = engine.query(".", "DNSKEY")
    if keys.status != OK:
        return stop("incomplete", f"Could not fetch the root DNSKEY ({keys.status})")
    matched = _matching_keys(dns.name.root, anchor_ds, keys.rrset)
    if not _signed_by(dns.name.root, keys.rrset, keys.rrsigs, matched):
        return stop("invalid", "Root DNSKEY set does not validate against the trust anchors")
    result["steps"].append({"zone": ".", "status": "valid"})
    trusted = list(keys.rrset)
    parent = dns.name.root

    for zone in zones[1:]:
        text = zone.to_text()
        ds = engine.query(text, "DS")
        if ds.status not in (OK, NODATA):
            return stop("incomplete", f"Could not fetch DS for {text} ({ds.status})")
        if ds.status == NODATA:
            if zone == zones[-1]:
                return stop("invalid", f"No DS for {text} at its parent")
            continue  # no es un corte de zona, seguimos con las mismas claves
        if not _signed_by(parent, ds.rrset, ds.rrsigs, trusted):
            return stop("invalid", f"DS RRset for {text} is not signed by the parent zone")
        keys = engine.query(text, "DNSKEY")
        if keys.status != OK:
            return stop("incomplete", f"Could not fetch DNSKEY for {text} ({keys.status})")
        matched = _matching_keys(zone, ds.rrset, keys.rrset)
        if not _signed_by(zone, keys.rrset, keys.rrsigs, matched):
            return stop("invalid", f"DNSKEY set of {text} does not validate against its DS")
        result["steps"].append({"zone": text, "status": "valid"})
        trusted = list(keys.rrset)
        parent = zone
    return result


def audit_dnssec(
    engine: DnsEngine, domain: str, anchors=ROOT_TRUST_ANCHORS
) -> tuple[dict, list[Finding]]:
    ds = engine.query(domain, "DS")
    dnskey = engine.query(domain, "DNSKEY")
    status: dict = {
        "status": "unsigned",
        "ds": ds.records,
        "dnskey": [_key_info(r) for r in dnskey.rrset] if dnskey.rrset else [],
        "ad_flag": dnskey.ad_flag,
        "validation": None,
        "denial": None,
        "note": NOTE,
    }
    findings: list[Finding] = []
    has_ds, has_key = ds.status == OK, dnskey.status == OK

    if has_ds and dnskey.status not in ANSWERED:
        # con DS pero sin poder sacar el DNSKEY, un resolver que valida suele dar SERVFAIL
        status["status"] = "broken"
        findings.append(_broken(domain, f"DS present but DNSKEY query failed: {dnskey.status}"))
        return status, findings
    if ds.status not in ANSWERED or dnskey.status not in ANSWERED:
        status["status"] = "error"
        findings.append(
            Finding(
                "DNSSEC-000",
                Severity.INFO,
                "DNSSEC could not be checked",
                "The DS or DNSKEY query failed.",
                f"DS: {ds.status}, DNSKEY: {dnskey.status}",
                "Retry later.",
                CATEGORY,
            )
        )
        return status, findings

    if not has_ds and not has_key:
        findings.append(
            Finding(
                "DNSSEC-001",
                Severity.LOW,
                "DNSSEC is not enabled",
                "Without DNSSEC, resolvers cannot detect forged DNS answers (cache poisoning).",
                f"No DS record for {domain} at the parent and no DNSKEY in the zone",
                "Enable DNSSEC at your DNS provider and publish the DS record at your registrar.",
                CATEGORY,
                "RFC 4033",
            )
        )
        return status, findings
    if has_key and not has_ds:
        status["status"] = "no_chain"
        findings.append(
            Finding(
                "DNSSEC-002",
                Severity.MEDIUM,
                "Zone is signed but no DS record at the parent",
                "The zone publishes DNSKEY records but the chain of trust is not established, "
                "so validating resolvers treat it as unsigned.",
                f"DNSKEY tags: {', '.join(str(k['key_tag']) for k in status['dnskey'])}; no DS",
                "Publish the DS record at your registrar.",
                CATEGORY,
                "RFC 4035 section 5",
            )
        )
        return status, findings
    if has_ds and not has_key:
        status["status"] = "broken"
        findings.append(_broken(domain, "DS published at the parent but the zone has no DNSKEY"))
        return status, findings

    validation = validate_locally(domain, ds, dnskey)
    status["validation"] = validation
    if validation["errors"]:
        status["status"] = "broken"
        findings.append(_broken(domain, "\n".join(validation["errors"])))
    else:
        status["status"] = "signed"
        chain = validate_chain(engine, domain, anchors)
        validation["chain"] = chain
        if chain["status"] == "invalid":
            status["status"] = "broken"
            findings.append(_chain_broken(domain, chain["error"]))

    if status["status"] == "signed":
        status["denial"], denial_findings = audit_denial(engine, domain)
        findings += denial_findings

    algorithms = {k["algorithm_number"]: k["algorithm"] for k in status["dnskey"]}
    deprecated = sorted(name for num, name in algorithms.items() if num in DEPRECATED_ALGORITHMS)
    if deprecated:
        findings.append(
            Finding(
                "DNSSEC-005",
                Severity.MEDIUM,
                "Deprecated DNSSEC algorithm",
                "These algorithms must no longer be used for signing.",
                ", ".join(deprecated),
                "Roll over to ECDSAP256SHA256 (13) or ED25519 (15).",
                CATEGORY,
                "RFC 8624",
            )
        )
    if ds.rrset and all(r.digest_type == 1 for r in ds.rrset):
        findings.append(
            Finding(
                "DNSSEC-006",
                Severity.LOW,
                "DS records use only SHA-1",
                "SHA-1 DS digests are deprecated.",
                "\n".join(ds.records),
                "Publish a SHA-256 (digest type 2) DS record.",
                CATEGORY,
                "RFC 8624",
            )
        )
    if status["status"] == "signed" and not dnskey.ad_flag:
        findings.append(
            Finding(
                "DNSSEC-007",
                Severity.INFO,
                "Resolver did not set the AD flag",
                "The zone looks correctly signed, but the configured resolver did not report "
                "the answer as authenticated. The resolver may simply not validate DNSSEC.",
                f"Resolver: {', '.join(engine.nameservers)}; AD=0",
                "Use a validating resolver (e.g. 1.1.1.1 or 9.9.9.9) to confirm.",
                CATEGORY,
                "RFC 4035 section 3.2.3",
            )
        )
    return status, findings


def audit_denial(engine: DnsEngine, domain: str) -> tuple[dict, list[Finding]]:
    """Mira NSEC/NSEC3 con una sola consulta a un nombre aleatorio que no existe."""
    probe = f"_dnsinspector-{secrets.token_hex(6)}.{domain}"
    records = engine.query_denial(probe)
    info: dict = {"type": None, "iterations": None, "salt": None}
    findings: list[Finding] = []
    nsec3 = [r for rrset in records if rrset.rdtype == dns.rdatatype.NSEC3 for r in rrset]
    if nsec3:
        info.update(type="NSEC3", iterations=nsec3[0].iterations, salt=nsec3[0].salt.hex())
        iterations = max(r.iterations for r in nsec3)
        salted = any(r.salt for r in nsec3)
        if iterations > 0:
            # mas de 150 iteraciones: muchos resolvers lo tratan como inseguro (RFC 9276)
            severity = Severity.MEDIUM if iterations > 150 else Severity.LOW
            findings.append(
                Finding(
                    "DNSSEC-009",
                    severity,
                    "NSEC3 uses additional hash iterations",
                    "RFC 9276 says the iteration count MUST be 0: extra iterations only cost "
                    "CPU and resolvers may treat zones with more than 150 as insecure.",
                    f"{domain}: NSEC3 iterations = {iterations}",
                    "Re-sign the zone with NSEC3 iterations set to 0.",
                    CATEGORY,
                    "RFC 9276 section 3.1",
                )
            )
        if salted:
            findings.append(
                Finding(
                    "DNSSEC-010",
                    Severity.LOW,
                    "NSEC3 uses a salt",
                    "RFC 9276 recommends an empty salt: it adds no real protection and "
                    "makes key and salt rollovers harder.",
                    f"{domain}: NSEC3 salt = {info['salt']}",
                    "Re-sign the zone with an empty NSEC3 salt.",
                    CATEGORY,
                    "RFC 9276 section 3.1",
                )
            )
    elif records:
        info["type"] = "NSEC"
        # si el NSEC es del propio nombre pedido es una "mentira blanca": no se puede recorrer
        walkable = any(str(r.name).lower() != probe.lower() + "." for r in records)
        findings += [_nsec_walking(domain)] if walkable else []
    return info, findings


def _nsec_walking(domain: str) -> Finding:
    return Finding(
        "DNSSEC-011",
        Severity.LOW,
        "Zone uses NSEC (names can be enumerated)",
        "NSEC records link each name to the next one, so anyone can walk the zone "
        "and list every name in it.",
        f"{domain}: NSEC records returned for a non-existent name",
        "Switch to NSEC3 (iterations 0) or NSEC white lies if the names are sensitive.",
        CATEGORY,
        "RFC 4035 section 5.2 and RFC 9276",
    )


def _broken(domain: str, evidence: str) -> Finding:
    return Finding(
        "DNSSEC-003",
        Severity.HIGH,
        "DNSSEC chain of trust is broken",
        "Validating resolvers will reject answers for this domain (SERVFAIL), making it "
        "unreachable for a large share of users.",
        f"{domain}: {evidence}",
        "Fix the DS at the registrar so it matches the active KSK, or remove DS before "
        "disabling DNSSEC.",
        CATEGORY,
        "RFC 4035 section 5",
    )


def _chain_broken(domain: str, evidence: str) -> Finding:
    return Finding(
        "DNSSEC-008",
        Severity.HIGH,
        "Chain of trust does not validate up to the root",
        "The zone looks signed, but the chain from the IANA root trust anchor down to the "
        "domain does not validate, so validating resolvers will reject it.",
        f"{domain}: {evidence}",
        "Check the DS record at the registrar and the signatures of the parent zones.",
        CATEGORY,
        "RFC 4035 section 5",
    )
