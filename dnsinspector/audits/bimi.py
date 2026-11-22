"""Auditoria BIMI: registro para mostrar el logo de la marca en el correo.

Solo miramos el TXT en default._bimi.<dominio>. No descargamos el SVG ni el
certificado (VMC), asi que no comprobamos que el logo sea valido.
"""

from dnsinspector.audits import parse_tag_list
from dnsinspector.audits.mta_sts import receives_mail
from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "Email security / BIMI"
REF = "draft-brand-indicators-for-message-identification"
NOTE = "Only the DNS record is checked; the SVG logo and the VMC certificate are not downloaded."


def parse_bimi(record: str) -> tuple[dict[str, str], list[str]]:
    tags, errors = parse_tag_list(record)
    if not record.startswith("v=BIMI1"):
        errors.append("Record must start with 'v=BIMI1'")
    if "l" not in tags:
        errors.append("Missing required tag 'l' (logo URL)")
    elif tags["l"] and not (
        tags["l"].lower().startswith("https://") and tags["l"].lower().endswith(".svg")
    ):
        errors.append("'l' must be an https:// URL to an .svg file")
    if tags.get("a") and not tags["a"].lower().startswith("https://"):
        errors.append("'a' must be an https:// URL")
    return tags, errors


def dmarc_enforced(dmarc: dict) -> bool:
    # BIMI pide DMARC con quarantine o reject al 100% y sin sp=none
    tags = dmarc.get("tags") or {}
    return (
        dmarc.get("status") in ("ok", "weak")
        and dmarc.get("policy") in ("quarantine", "reject")
        and tags.get("pct", "100") == "100"
        and tags.get("sp", "").lower() != "none"
    )


def audit_bimi(
    engine: DnsEngine, domain: str, mx: QueryResult, dmarc: dict
) -> tuple[dict, list[Finding]]:
    if not receives_mail(mx):
        return {"status": "not_applicable", "note": "The domain has no MX records."}, []

    name = f"default._bimi.{domain}"
    query = engine.query(name, "TXT")
    if query.status not in (OK, NODATA, NXDOMAIN):
        return {"status": "error", "name": name, "error": query.status}, []

    enforced = dmarc_enforced(dmarc)
    status: dict = {"status": "missing", "name": name, "dmarc_ready": enforced, "note": NOTE}
    records = [r for r in query.records if r.startswith("v=BIMI1")]
    findings: list[Finding] = []

    if not records:
        if enforced:
            findings.append(
                Finding(
                    "BIMI-001",
                    Severity.INFO,
                    "No BIMI record",
                    "DMARC is already enforced, so the domain could publish BIMI to show its "
                    "logo next to messages in supporting mail clients.",
                    f"No TXT record at {name}",
                    "Optional: publish 'v=BIMI1; l=https://<host>/logo.svg; a=<VMC URL>'.",
                    CATEGORY,
                    REF,
                )
            )
        return status, findings

    record = records[0]
    tags, errors = parse_bimi(record)
    if len(records) > 1:
        errors.append("More than one BIMI record")
    status.update(record=record, tags=tags, errors=errors, status="invalid" if errors else "ok")
    if errors:
        findings.append(
            Finding(
                "BIMI-002",
                Severity.LOW,
                "Invalid BIMI record",
                "Mail clients ignore an invalid BIMI record, so the logo is not shown.",
                record + "\n" + "\n".join(errors),
                "Fix the listed problems.",
                CATEGORY,
                REF,
            )
        )
    if not enforced:
        findings.append(
            Finding(
                "BIMI-003",
                Severity.LOW,
                "BIMI published but DMARC is not enforced",
                "Mail clients only show BIMI logos when DMARC is p=quarantine or p=reject at "
                "100% (and sp is not none).",
                record,
                "Move DMARC to p=quarantine or p=reject with pct=100.",
                CATEGORY,
                REF,
            )
        )
    if not errors and tags.get("l") and not tags.get("a"):
        findings.append(
            Finding(
                "BIMI-004",
                Severity.INFO,
                "BIMI record has no certificate (a=)",
                "Major providers such as Gmail and Apple Mail only show the logo with a Verified "
                "Mark Certificate (VMC) or Common Mark Certificate.",
                record,
                "Add 'a=' with the URL of your VMC/CMC if you want the logo in those clients.",
                CATEGORY,
                REF,
            )
        )
    return status, findings
