"""Auditoria DNSSEC.

Comprobamos: DS en el padre, DNSKEY en la zona, que algun DS coincida con una DNSKEY
y que la firma (RRSIG) del conjunto DNSKEY sea valida. NO validamos la cadena entera
hasta la raiz, eso se explica en el informe.
"""

import dns.dnssec
import dns.exception
import dns.name

from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "DNSSEC"
NOTE = (
    "DNSInspector checks that the parent DS matches a DNSKEY and that the DNSKEY set is "
    "correctly signed. It does not validate the full chain of trust up to the root; the AD "
    "flag is reported as returned by the configured resolver."
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


def audit_dnssec(engine: DnsEngine, domain: str) -> tuple[dict, list[Finding]]:
    ds = engine.query(domain, "DS")
    dnskey = engine.query(domain, "DNSKEY")
    status: dict = {
        "status": "unsigned",
        "ds": ds.records,
        "dnskey": [_key_info(r) for r in dnskey.rrset] if dnskey.rrset else [],
        "ad_flag": dnskey.ad_flag,
        "validation": None,
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
