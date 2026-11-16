"""Comprobaciones basicas de los registros DNS del dominio."""

from dnsinspector.dns_engine import ERROR, NXDOMAIN, OK, TIMEOUT, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "DNS configuration"


def audit_records(domain: str, records: dict[str, QueryResult]) -> list[Finding]:
    findings: list[Finding] = []
    failed = [r for r in records.values() if r.status in (TIMEOUT, ERROR)]
    if failed:
        findings.append(
            Finding(
                "DNS-001",
                Severity.MEDIUM,
                "Some DNS queries failed",
                "Timeouts or server failures can mean a broken or lame delegation, or an "
                "overloaded name server. Results for these types are incomplete.",
                "\n".join(f"{r.rtype}: {r.status} {r.error or ''}".strip() for r in failed),
                "Check that every NS for the zone answers authoritatively.",
                CATEGORY,
                "RFC 1034",
            )
        )

    ns = records.get("NS")
    if ns and ns.status == OK and len(ns.records) < 2:
        findings.append(
            Finding(
                "DNS-002",
                Severity.LOW,
                "Only one name server",
                "A single name server is a single point of failure.",
                "\n".join(ns.records),
                "Use at least two name servers, ideally on different networks.",
                CATEGORY,
                "RFC 1034 section 4.1",
            )
        )

    mx = records.get("MX")
    if mx and mx.status == OK and mx.records == ["0 ."]:
        findings.append(
            Finding(
                "DNS-003",
                Severity.INFO,
                "Domain does not accept mail (null MX)",
                "A null MX explicitly says the domain receives no mail.",
                "MX 0 .",
                "No action needed if the domain does not use email.",
                CATEGORY,
                "RFC 7505",
            )
        )
    elif mx and mx.status != OK and mx.status not in (TIMEOUT, ERROR):
        findings.append(
            Finding(
                "DNS-004",
                Severity.INFO,
                "No MX records",
                "Mail will fall back to the A/AAAA record. If the domain should not receive mail, "
                "a null MX makes that explicit.",
                f"MX {domain}: {mx.status}",
                "Publish MX records, or 'MX 0 .' if the domain does not receive mail.",
                CATEGORY,
                "RFC 7505",
            )
        )

    a, aaaa = records.get("A"), records.get("AAAA")
    if a and aaaa and a.status == OK and aaaa.status != OK and aaaa.status not in (TIMEOUT, ERROR):
        findings.append(
            Finding(
                "DNS-005",
                Severity.INFO,
                "No IPv6 address (AAAA)",
                "The domain is only reachable over IPv4.",
                f"AAAA {domain}: {aaaa.status}",
                "Add AAAA records if your hosting supports IPv6.",
                CATEGORY,
            )
        )
    return findings


def domain_exists(records: dict[str, QueryResult]) -> bool:
    return not all(r.status == NXDOMAIN for r in records.values())
