"""Auditoria SPF (RFC 7208)."""

import ipaddress
import re

from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine
from dnsinspector.findings import Finding, Severity

LOOKUP_LIMIT = 10  # RFC 7208 4.6.4
REF = "RFC 7208"
CATEGORY = "Email security / SPF"

MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
# estos terminos gastan una consulta DNS cada uno
LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
_TERM_RE = re.compile(r"^([+\-~?]?)([a-z0-9]+)([:/=].*)?$", re.IGNORECASE)


def find_spf_records(txt_records: list[str]) -> list[str]:
    # un SPF empieza por "v=spf1" seguido de espacio o fin
    return [r for r in txt_records if r.lower() == "v=spf1" or r.lower().startswith("v=spf1 ")]


def parse_spf(record: str) -> tuple[list[dict], list[str]]:
    """Separa el registro en terminos. Devuelve (terminos, errores de sintaxis)."""
    terms: list[dict] = []
    errors: list[str] = []
    for raw in record.split()[1:]:
        match = _TERM_RE.match(raw)
        if not match:
            errors.append(f"Unparseable term '{raw}'")
            continue
        qualifier, name, rest = match.group(1) or "+", match.group(2).lower(), match.group(3) or ""
        if rest.startswith("="):  # modificador, ej: redirect=
            if match.group(1):
                errors.append(f"Modifier '{raw}' cannot have a qualifier")
            terms.append({"kind": "modifier", "name": name, "value": rest[1:], "raw": raw})
            continue
        if name not in MECHANISMS:
            errors.append(f"Unknown mechanism '{raw}'")
            continue
        value = rest[1:] if rest.startswith(":") else rest
        error = _check_mechanism(name, value)
        if error:
            errors.append(f"{error} in '{raw}'")
        terms.append(
            {"kind": "mechanism", "qualifier": qualifier, "name": name, "value": value, "raw": raw}
        )
    names = [t["name"] for t in terms if t["kind"] == "modifier"]
    for modifier in ("redirect", "exp"):
        if names.count(modifier) > 1:
            errors.append(f"Modifier '{modifier}' appears more than once")
    return terms, errors


def _check_mechanism(name: str, value: str) -> str | None:
    if name == "all" and value:
        return "'all' does not take a value"
    if name in ("include", "exists") and not value:
        return f"'{name}' requires a domain"
    if name in ("ip4", "ip6"):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return f"Invalid {name} address"
        if net.version != int(name[-1]):
            return f"Wrong IP version for {name}"
    return None


def count_lookups(
    engine: DnsEngine, domain: str, visited: set[str] | None = None, state: dict | None = None
) -> dict:
    """Cuenta las consultas DNS que haria un receptor, siguiendo include y redirect.

    Para en cuanto se pasa del limite, asi no hacemos consultas infinitas.
    """
    visited = visited if visited is not None else set()
    state = state if state is not None else {"count": 0, "errors": [], "chain": []}
    visited.add(domain)
    txt = engine.query(domain, "TXT")
    if txt.status not in (OK, NODATA, NXDOMAIN):
        # un fallo de red no es un error de configuracion, lo apuntamos aparte
        state.setdefault("unchecked", []).append(f"{domain}: {txt.status}")
        return state
    records = find_spf_records(txt.records)
    if len(records) != 1:
        state["errors"].append(f"{domain}: {'no' if not records else 'multiple'} SPF record")
        return state
    terms, _ = parse_spf(records[0])
    for term in terms:
        is_modifier = term["kind"] == "modifier"
        if term["name"] not in LOOKUP_TERMS or (is_modifier and term["name"] != "redirect"):
            continue
        state["count"] += 1
        if state["count"] > LOOKUP_LIMIT:
            return state
        target = term["value"].lower().rstrip(".")
        if term["name"] in ("include", "redirect") and target:
            state["chain"].append(f"{domain} -> {target}")
            if "%" in target:  # macros: no se pueden expandir sin el mensaje real
                continue
            if target in visited:
                state["errors"].append(f"Loop detected: {target} included again")
                continue
            count_lookups(engine, target, visited, state)
            if state["count"] > LOOKUP_LIMIT:
                return state
    return state


def audit_spf(engine: DnsEngine, domain: str) -> tuple[dict, list[Finding]]:
    txt = engine.query(domain, "TXT")
    status: dict = {"status": "missing", "records": [], "lookup_count": None, "all": None}
    findings: list[Finding] = []

    if txt.status not in (OK, NODATA, NXDOMAIN):
        status["status"] = "error"
        findings.append(
            Finding(
                "SPF-000",
                Severity.INFO,
                "SPF could not be checked",
                "The TXT query for the domain failed, so SPF was not evaluated.",
                f"TXT {domain}: {txt.status} {txt.error or ''}".strip(),
                "Retry later or check the domain's authoritative name servers.",
                CATEGORY,
            )
        )
        return status, findings

    records = find_spf_records(txt.records)
    status["records"] = records
    if not records:
        findings.append(
            Finding(
                "SPF-001",
                Severity.MEDIUM,
                "No SPF record",
                "Receivers cannot check which servers may send mail for this domain, which makes "
                "spoofing easier. Domains that never send mail should still publish 'v=spf1 -all'.",
                f"No TXT record starting with 'v=spf1' at {domain}",
                "Publish one SPF record listing your mail senders and ending in '-all' or '~all'.",
                CATEGORY,
                REF,
            )
        )
        return status, findings

    if len(records) > 1:
        status["status"] = "invalid"
        findings.append(
            Finding(
                "SPF-002",
                Severity.HIGH,
                "Multiple SPF records",
                "RFC 7208 requires exactly one SPF record. With more than one, receivers return "
                "'permerror' and SPF gives no protection.",
                "\n".join(records),
                "Merge all SPF records into a single TXT record.",
                CATEGORY,
                f"{REF} section 4.5",
            )
        )
        return status, findings

    record = records[0]
    status["record"] = record
    terms, errors = parse_spf(record)
    if errors:
        findings.append(
            Finding(
                "SPF-003",
                Severity.HIGH,
                "SPF syntax errors",
                "Receivers treat a syntactically invalid SPF record as 'permerror'.",
                f"{record}\n" + "\n".join(errors),
                "Fix the listed terms.",
                CATEGORY,
                f"{REF} section 12",
            )
        )

    mechanisms = [t for t in terms if t["kind"] == "mechanism"]
    all_terms = [t for t in mechanisms if t["name"] == "all"]
    has_redirect = any(t["name"] == "redirect" for t in terms if t["kind"] == "modifier")
    final_all = all_terms[-1]["qualifier"] + "all" if all_terms else None
    status["all"] = final_all
    findings.extend(_all_findings(record, mechanisms, all_terms, has_redirect))

    if any(t["name"] == "ptr" for t in mechanisms):
        findings.append(
            Finding(
                "SPF-009",
                Severity.LOW,
                "SPF uses the deprecated 'ptr' mechanism",
                "'ptr' is slow, unreliable and many receivers ignore it.",
                record,
                "Replace 'ptr' with 'ip4', 'ip6' or 'include'.",
                CATEGORY,
                f"{REF} section 5.5",
            )
        )

    lookups = count_lookups(engine, domain)
    status["lookup_count"] = lookups["count"]
    status["include_chain"] = lookups["chain"]
    status["unchecked_includes"] = lookups.get("unchecked", [])
    nested_errors = [e for e in lookups["errors"] if not e.startswith(f"{domain}:")]
    if lookups["count"] > LOOKUP_LIMIT:
        findings.append(
            Finding(
                "SPF-008",
                Severity.HIGH,
                "SPF exceeds the 10 DNS lookup limit",
                "Receivers stop evaluating after 10 lookups and return 'permerror', so SPF fails "
                "for legitimate mail.",
                f"More than {LOOKUP_LIMIT} lookups counted through include/redirect:\n"
                + "\n".join(lookups["chain"]),
                "Remove unused includes or replace them with ip4/ip6 ranges.",
                CATEGORY,
                f"{REF} section 4.6.4",
            )
        )
    elif lookups["count"] >= 8:
        findings.append(
            Finding(
                "SPF-010",
                Severity.LOW,
                "SPF is close to the 10 lookup limit",
                "Adding one more provider may push the record over the limit.",
                f"{lookups['count']} of {LOOKUP_LIMIT} lookups used",
                "Review includes before adding new senders.",
                CATEGORY,
                f"{REF} section 4.6.4",
            )
        )
    if status["unchecked_includes"]:
        findings.append(
            Finding(
                "SPF-013",
                Severity.INFO,
                "Some SPF includes could not be resolved",
                "DNS queries for these includes failed, so the lookup count is a lower bound.",
                "\n".join(status["unchecked_includes"]),
                "Run the analysis again later.",
                CATEGORY,
            )
        )
    if nested_errors:
        findings.append(
            Finding(
                "SPF-011",
                Severity.HIGH,
                "Broken include or redirect target",
                "An include/redirect points to a domain without exactly one SPF record, which "
                "causes 'permerror', or the chain loops.",
                "\n".join(nested_errors),
                "Fix or remove the broken include/redirect.",
                CATEGORY,
                f"{REF} sections 5.2 and 6.1",
            )
        )

    # invalid = los receptores darian permerror; weak = funciona pero protege poco
    serious = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
    if errors or nested_errors or lookups["count"] > LOOKUP_LIMIT:
        status["status"] = "invalid"
    elif any(f.severity in serious for f in findings):
        status["status"] = "weak"
    else:
        status["status"] = "ok"
    return status, findings


def _all_findings(
    record: str, mechanisms: list[dict], all_terms: list[dict], has_redirect: bool
) -> list[Finding]:
    findings: list[Finding] = []
    if not all_terms:
        if not has_redirect:
            findings.append(
                Finding(
                    "SPF-007",
                    Severity.MEDIUM,
                    "SPF has no 'all' mechanism",
                    "Without 'all' or 'redirect', mail from unlisted servers gets a 'neutral' "
                    "result, which gives little protection.",
                    record,
                    "End the record with '-all' (or '~all' while testing).",
                    CATEGORY,
                    f"{REF} section 4.7",
                )
            )
        return findings

    qualifier = all_terms[-1]["qualifier"]
    if qualifier == "+":
        findings.append(
            Finding(
                "SPF-004",
                Severity.CRITICAL,
                "SPF allows any server to send mail ('+all')",
                "'+all' authorizes every IP on the Internet to send mail as this domain.",
                record,
                "Replace '+all' with '-all' after listing your real senders.",
                CATEGORY,
                f"{REF} section 5.1",
            )
        )
    elif qualifier == "?":
        findings.append(
            Finding(
                "SPF-005",
                Severity.MEDIUM,
                "SPF ends in neutral '?all'",
                "'?all' says nothing about unlisted servers, so it does not help block spoofing.",
                record,
                "Use '-all' or '~all'.",
                CATEGORY,
                f"{REF} section 8.2",
            )
        )
    elif qualifier == "~":
        findings.append(
            Finding(
                "SPF-006",
                Severity.INFO,
                "SPF ends in softfail '~all'",
                "'~all' marks unlisted senders as suspicious but does not ask for rejection. "
                "This is common and fine when DMARC is enforced.",
                record,
                "Consider '-all' once all senders are listed.",
                CATEGORY,
                f"{REF} section 8.4",
            )
        )
    if len(all_terms) > 1 or mechanisms[-1]["name"] != "all":
        findings.append(
            Finding(
                "SPF-012",
                Severity.LOW,
                "Terms after 'all' are ignored",
                "Evaluation stops at the first 'all', so anything after it has no effect.",
                record,
                "Move 'all' to the end and remove duplicates.",
                CATEGORY,
                f"{REF} section 5.1",
            )
        )
    return findings
