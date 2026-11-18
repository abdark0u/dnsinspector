"""Auditoria DMARC (RFC 7489)."""

from publicsuffix2 import get_sld

from dnsinspector.audits import parse_tag_list
from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine
from dnsinspector.findings import Finding, Severity

REF = "RFC 7489"
CATEGORY = "Email security / DMARC"
POLICIES = ("none", "quarantine", "reject")
KNOWN_TAGS = {
    "v",
    "p",
    "sp",
    "rua",
    "ruf",
    "pct",
    "adkim",
    "aspf",
    "fo",
    "rf",
    "ri",
    "np",
    "t",
    "psd",
}


def parse_dmarc(record: str) -> tuple[dict[str, str], list[str]]:
    """Valida la sintaxis basica de un registro DMARC."""
    tags, errors = parse_tag_list(record)
    if not record.strip().replace(" ", "").startswith("v=DMARC1"):
        errors.append("Record must start with 'v=DMARC1'")
    if "p" not in tags:
        errors.append("Missing required tag 'p'")
    elif tags["p"].lower() not in POLICIES:
        errors.append(f"Invalid policy p={tags['p']}")
    if "sp" in tags and tags["sp"].lower() not in POLICIES:
        errors.append(f"Invalid subdomain policy sp={tags['sp']}")
    for tag in ("adkim", "aspf"):
        if tag in tags and tags[tag].lower() not in ("r", "s"):
            errors.append(f"{tag} must be 'r' or 's'")
    if "pct" in tags and not (tags["pct"].isdigit() and 0 <= int(tags["pct"]) <= 100):
        errors.append("pct must be an integer between 0 and 100")
    return tags, errors


def _bad_uris(value: str) -> list[str]:
    # rua/ruf son listas de URIs, normalmente mailto:
    uris = (u.strip() for u in value.split(","))
    return [uri for uri in uris if uri and not uri.lower().startswith("mailto:")]


def _lookup(engine: DnsEngine, domain: str) -> tuple[str, list[str], str]:
    query = engine.query(f"_dmarc.{domain}", "TXT")
    records = [r for r in query.records if r.replace(" ", "").lower().startswith("v=dmarc1")]
    return query.status, records, query.error or ""


def audit_dmarc(engine: DnsEngine, domain: str) -> tuple[dict, list[Finding]]:
    status: dict = {"status": "missing", "record": None, "tags": {}, "source": f"_dmarc.{domain}"}
    findings: list[Finding] = []

    dns_status, records, error = _lookup(engine, domain)
    if dns_status not in (OK, NODATA, NXDOMAIN):
        status["status"] = "error"
        findings.append(
            Finding(
                "DMARC-000",
                Severity.INFO,
                "DMARC could not be checked",
                "The DMARC TXT query failed, so DMARC was not evaluated.",
                f"TXT _dmarc.{domain}: {dns_status} {error}".strip(),
                "Retry later.",
                CATEGORY,
            )
        )
        return status, findings

    # dominio organizativo segun la Public Suffix List (lista incluida, sin red)
    org = get_sld(domain) or domain
    if not records and org != domain:
        _, records, _ = _lookup(engine, org)
        if records:
            status["source"] = f"_dmarc.{org}"
            status["inherited"] = True

    if not records:
        findings.append(
            Finding(
                "DMARC-001",
                Severity.HIGH,
                "No DMARC record",
                "Without DMARC, receivers have no instructions for mail that fails SPF/DKIM "
                "alignment and the owner gets no reports, so the domain is easier to spoof.",
                f"No 'v=DMARC1' TXT record at _dmarc.{domain}",
                "Start with 'v=DMARC1; p=none; rua=mailto:dmarc@<domain>', review the reports, "
                "then move to p=quarantine or p=reject.",
                CATEGORY,
                f"{REF} section 6.1",
            )
        )
        return status, findings

    if len(records) > 1:
        status["status"] = "invalid"
        findings.append(
            Finding(
                "DMARC-002",
                Severity.HIGH,
                "Multiple DMARC records",
                "With more than one record, receivers ignore DMARC completely.",
                "\n".join(records),
                "Keep a single DMARC record.",
                CATEGORY,
                f"{REF} section 6.6.3",
            )
        )
        return status, findings

    record = records[0]
    tags, errors = parse_dmarc(record)
    status.update(record=record, tags=tags)
    if errors:
        status["status"] = "invalid"
        findings.append(
            Finding(
                "DMARC-003",
                Severity.HIGH,
                "DMARC syntax errors",
                "Receivers may ignore a DMARC record with invalid syntax.",
                record + "\n" + "\n".join(errors),
                "Fix the listed tags.",
                CATEGORY,
                f"{REF} section 6.4",
            )
        )
        return status, findings

    policy = tags["p"].lower()
    status["policy"] = policy
    findings.extend(_policy_findings(record, tags, policy))
    weak = any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)
    status["status"] = "weak" if weak else "ok"
    return status, findings


def _policy_findings(record: str, tags: dict[str, str], policy: str) -> list[Finding]:
    findings: list[Finding] = []
    if policy == "none":
        findings.append(
            Finding(
                "DMARC-004",
                Severity.MEDIUM,
                "DMARC policy is 'none' (monitoring only)",
                "p=none only collects reports; spoofed mail is still delivered normally.",
                record,
                "After reviewing reports, move to p=quarantine and then p=reject.",
                CATEGORY,
                f"{REF} section 6.3",
            )
        )
    sub_policy = tags.get("sp", "").lower()
    if policy != "none" and sub_policy == "none":
        findings.append(
            Finding(
                "DMARC-005",
                Severity.MEDIUM,
                "Subdomain policy is 'none'",
                "sp=none lets attackers spoof any subdomain even though the main domain is "
                "protected.",
                record,
                "Remove sp or set it to quarantine/reject.",
                CATEGORY,
                f"{REF} section 6.3",
            )
        )
    pct = int(tags.get("pct", "100"))
    if policy != "none" and pct < 100:
        findings.append(
            Finding(
                "DMARC-006",
                Severity.LOW,
                f"DMARC policy applies only to {pct}% of mail",
                "The rest of failing mail is handled as if the policy were one step weaker.",
                record,
                "Raise pct to 100 once you are confident.",
                CATEGORY,
                f"{REF} section 6.3",
            )
        )
    if "rua" not in tags:
        findings.append(
            Finding(
                "DMARC-007",
                Severity.LOW,
                "No aggregate report address (rua)",
                "Without rua you get no visibility into who sends mail using your domain.",
                record,
                "Add rua=mailto:<address> to receive aggregate reports.",
                CATEGORY,
                f"{REF} section 7.2",
            )
        )
    bad = _bad_uris(tags.get("rua", "")) + _bad_uris(tags.get("ruf", ""))
    if bad:
        findings.append(
            Finding(
                "DMARC-008",
                Severity.LOW,
                "Invalid report URI",
                "Report addresses must be 'mailto:' URIs; others are usually ignored.",
                ", ".join(bad),
                "Use rua=mailto:address@example.com.",
                CATEGORY,
                f"{REF} section 6.2",
            )
        )
    unknown = sorted(set(tags) - KNOWN_TAGS)
    if unknown:
        findings.append(
            Finding(
                "DMARC-009",
                Severity.INFO,
                "Unknown DMARC tags",
                "Unknown tags are ignored by receivers, which may hide a typo.",
                ", ".join(unknown),
                "Check the tag names.",
                CATEGORY,
                f"{REF} section 6.3",
            )
        )
    return findings
