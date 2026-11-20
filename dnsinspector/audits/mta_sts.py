"""Auditoria MTA-STS (RFC 8461) y TLS-RPT (RFC 8460).

Solo miramos los registros TXT. El fichero de politica de MTA-STS esta en una web
(https://mta-sts.<dominio>/...) y no lo descargamos para seguir siendo solo DNS.
"""

import re

from dnsinspector.audits import parse_tag_list
from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "Email security / transport TLS"
NOTE = (
    "Only the DNS records are checked. The MTA-STS policy file served over HTTPS at "
    "mta-sts.<domain> is not downloaded."
)
_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")


def parse_mta_sts(record: str) -> tuple[dict[str, str], list[str]]:
    tags, errors = parse_tag_list(record)
    if not record.startswith("v=STSv1"):
        errors.append("Record must start with 'v=STSv1'")
    if "id" not in tags:
        errors.append("Missing required tag 'id'")
    elif not _ID_RE.match(tags["id"]):
        errors.append("'id' must be 1-32 letters or digits")
    return tags, errors


def parse_tls_rpt(record: str) -> tuple[dict[str, str], list[str]]:
    tags, errors = parse_tag_list(record)
    if not record.startswith("v=TLSRPTv1"):
        errors.append("Record must start with 'v=TLSRPTv1'")
    if "rua" not in tags:
        errors.append("Missing required tag 'rua'")
    else:
        for uri in (u.strip() for u in tags["rua"].split(",")):
            if not uri.lower().startswith(("mailto:", "https:")):
                errors.append(f"Report URI must be mailto: or https: ('{uri}')")
    return tags, errors


def _check(engine: DnsEngine, name: str, prefix: str, parser) -> dict:
    """Busca un registro TXT con el prefijo dado y lo valida."""
    query = engine.query(name, "TXT")
    if query.status not in (OK, NODATA, NXDOMAIN):
        return {"status": "error", "name": name, "error": query.status}
    records = [r for r in query.records if r.startswith(prefix)]
    if not records:
        return {"status": "missing", "name": name}
    if len(records) > 1:
        return {
            "status": "invalid",
            "name": name,
            "records": records,
            "errors": ["More than one record"],
        }
    tags, errors = parser(records[0])
    return {
        "status": "invalid" if errors else "ok",
        "name": name,
        "record": records[0],
        "tags": tags,
        "errors": errors,
    }


def receives_mail(mx: QueryResult) -> bool:
    # sin MX o con null MX el dominio no recibe correo y esto no aplica
    return mx.status == OK and mx.records != ["0 ."]


def audit_mta_sts(engine: DnsEngine, domain: str, mx: QueryResult) -> tuple[dict, list[Finding]]:
    if not receives_mail(mx):
        return {"status": "not_applicable", "note": "The domain has no MX records."}, []

    sts = _check(engine, f"_mta-sts.{domain}", "v=STSv1", parse_mta_sts)
    rpt = _check(engine, f"_smtp._tls.{domain}", "v=TLSRPTv1", parse_tls_rpt)
    findings: list[Finding] = []

    if sts["status"] == "missing":
        findings.append(
            Finding(
                "MTASTS-001",
                Severity.LOW,
                "No MTA-STS policy",
                "Without MTA-STS, sending servers fall back to plain text if an attacker strips "
                "STARTTLS, so inbound mail can be read or redirected on the network.",
                f"No 'v=STSv1' TXT record at {sts['name']}",
                "Publish an MTA-STS policy at https://mta-sts.<domain>/.well-known/mta-sts.txt "
                "and the _mta-sts TXT record, starting with mode: testing.",
                CATEGORY,
                "RFC 8461",
            )
        )
    elif sts["status"] == "invalid":
        findings.append(
            Finding(
                "MTASTS-002",
                Severity.LOW,
                "Invalid MTA-STS record",
                "Senders ignore an invalid MTA-STS record, so the policy is not applied.",
                "\n".join(sts.get("records") or [sts["record"]]) + "\n" + "\n".join(sts["errors"]),
                "Publish a single record like 'v=STSv1; id=20261120T000000'.",
                CATEGORY,
                "RFC 8461 section 3.1",
            )
        )

    if rpt["status"] == "missing":
        # sin MTA-STS el TLS-RPT es solo un extra, con MTA-STS es importante
        severity = Severity.LOW if sts["status"] == "ok" else Severity.INFO
        findings.append(
            Finding(
                "TLSRPT-001",
                severity,
                "No TLS-RPT record",
                "Without TLS-RPT you get no reports when other servers fail to deliver mail to "
                "you over TLS.",
                f"No 'v=TLSRPTv1' TXT record at {rpt['name']}",
                "Publish 'v=TLSRPTv1; rua=mailto:tls-reports@<domain>' at _smtp._tls.<domain>.",
                CATEGORY,
                "RFC 8460",
            )
        )
    elif rpt["status"] == "invalid":
        findings.append(
            Finding(
                "TLSRPT-002",
                Severity.LOW,
                "Invalid TLS-RPT record",
                "Senders ignore an invalid TLS-RPT record, so no reports are sent.",
                "\n".join(rpt.get("records") or [rpt["record"]]) + "\n" + "\n".join(rpt["errors"]),
                "Fix the listed problems.",
                CATEGORY,
                "RFC 8460 section 3",
            )
        )

    return {"status": sts["status"], "mta_sts": sts, "tls_rpt": rpt, "note": NOTE}, findings
