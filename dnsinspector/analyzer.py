"""Hace el analisis completo de un dominio y monta el informe."""

import logging
import time
from datetime import UTC, datetime

from dnsinspector import __version__
from dnsinspector.audits.bimi import audit_bimi
from dnsinspector.audits.dkim import audit_dkim
from dnsinspector.audits.dmarc import audit_dmarc
from dnsinspector.audits.dnssec import audit_dnssec
from dnsinspector.audits.mta_sts import audit_mta_sts, fetch_policy
from dnsinspector.audits.nameservers import audit_nameservers
from dnsinspector.audits.records import audit_records, domain_exists
from dnsinspector.audits.spf import audit_spf
from dnsinspector.dns_engine import LOOKUP_TYPES, DnsEngine
from dnsinspector.findings import Finding, Severity, sort_findings, summarize

logger = logging.getLogger(__name__)
MAX_SELECTORS = 5


def analyze(
    engine: DnsEngine,
    domain: str,
    selectors: list[str] | None = None,
    probe_dkim: bool = False,
    policy_fetcher=fetch_policy,
) -> dict:
    """Recibe un dominio ya validado y devuelve el informe como dict (listo para JSON)."""
    started = datetime.now(UTC)
    start = time.perf_counter()
    selectors = (selectors or [])[:MAX_SELECTORS]

    records = {rtype: engine.query(domain, rtype) for rtype in LOOKUP_TYPES}
    findings: list[Finding] = []
    report: dict = {
        "domain": domain,
        "started_at": started.isoformat(timespec="seconds"),
        "resolver": engine.nameservers,
        "tool_version": __version__,
        "records": {rtype: r.to_dict() for rtype, r in records.items()},
    }

    if not domain_exists(records):
        # si el dominio no existe no tiene sentido auditar el correo
        findings.append(
            Finding(
                "DNS-000",
                Severity.INFO,
                "Domain does not exist (NXDOMAIN)",
                "Every query returned NXDOMAIN, so no further checks were run.",
                f"{domain}: NXDOMAIN",
                "Check the spelling or the domain registration.",
                "DNS configuration",
                "RFC 8020",
            )
        )
        skipped = {"status": "skipped"}
        report.update(
            nameservers=skipped,
            spf=skipped,
            dkim=skipped,
            dmarc=skipped,
            dnssec=skipped,
            mta_sts=skipped,
            bimi=skipped,
        )
    else:
        findings += audit_records(domain, records)
        for key, audit in (
            ("nameservers", lambda: audit_nameservers(engine, domain, records["NS"])),
            ("spf", lambda: audit_spf(engine, domain)),
            ("dkim", lambda: audit_dkim(engine, domain, selectors, probe_dkim)),
            ("dmarc", lambda: audit_dmarc(engine, domain)),
            ("dnssec", lambda: audit_dnssec(engine, domain)),
            ("mta_sts", lambda: audit_mta_sts(engine, domain, records["MX"], policy_fetcher)),
            # va despues de dmarc porque usa su resultado
            ("bimi", lambda: audit_bimi(engine, domain, records["MX"], report["dmarc"])),
        ):
            status, audit_findings = audit()
            report[key] = status
            findings += audit_findings

    findings = sort_findings(findings)
    report["findings"] = [f.to_dict() for f in findings]
    report["summary"] = summarize(findings)
    report["duration_ms"] = round((time.perf_counter() - start) * 1000)
    logger.info(
        "analysis %s done in %sms, %s findings",
        domain,
        report["duration_ms"],
        report["summary"]["total"],
    )
    return report
