"""Auditoria MTA-STS (RFC 8461) y TLS-RPT (RFC 8460).

Miramos los registros TXT y, si el registro es valido, descargamos el fichero de
politica (https://mta-sts.<dominio>/.well-known/mta-sts.txt) con un fetcher inyectable.
"""

import http.client
import ipaddress
import re
import socket
import ssl

from dnsinspector.audits import parse_tag_list
from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "Email security / transport TLS"
NOTE = (
    "The MTA-STS policy file is downloaded only over HTTPS, from public IPs, without "
    "redirects, with a short timeout and a size limit."
)
MAX_POLICY_BYTES = 64 * 1024
FETCH_TIMEOUT = 5
MIN_MAX_AGE = 86400  # 1 dia; RFC 8461 recomienda semanas
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


class PolicyError(Exception):
    """No se pudo descargar la politica."""


def fetch_policy(host: str, ips: list[str]) -> str:
    """Descarga la politica por HTTPS conectando a una IP publica ya comprobada."""
    last = "no public address"
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            continue  # nunca mandamos trafico a IPs privadas
        try:
            raw = socket.create_connection((ip, 443), timeout=FETCH_TIMEOUT)
            raw.settimeout(FETCH_TIMEOUT)
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            last = f"{ip}: {exc}"
            continue
        conn = http.client.HTTPSConnection(host, timeout=FETCH_TIMEOUT)
        conn.sock = tls
        try:
            conn.request("GET", "/.well-known/mta-sts.txt", headers={"User-Agent": "DNSInspector"})
            resp = conn.getresponse()
            if resp.status != 200:  # los redirects (3xx) tampoco se siguen
                raise PolicyError(f"HTTP {resp.status}")
            body = resp.read(MAX_POLICY_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise PolicyError(str(exc) or type(exc).__name__) from exc
        finally:
            conn.close()
        if len(body) > MAX_POLICY_BYTES:
            raise PolicyError("policy larger than 64 KiB")
        return body.decode("utf-8", errors="replace")
    raise PolicyError(last)


def parse_policy(text: str) -> tuple[dict, list[str]]:
    policy: dict = {"mx": []}
    errors: list[str] = []
    for line in text.replace("\r", "").split("\n"):
        if ":" not in line:
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        if key == "mx":
            policy["mx"].append(value.lower())
        elif key:
            policy[key] = value
    if policy.get("version") != "STSv1":
        errors.append("version must be STSv1")
    if policy.get("mode") not in ("enforce", "testing", "none"):
        errors.append("mode must be enforce, testing or none")
    if not str(policy.get("max_age", "")).isdigit():
        errors.append("max_age must be a number of seconds")
    elif int(policy["max_age"]) > 31557600:
        errors.append("max_age is above one year")
    if not policy["mx"] and policy.get("mode") != "none":
        errors.append("at least one mx line is required")
    return policy, errors


def mx_matches(pattern: str, host: str) -> bool:
    host = host.rstrip(".").lower()
    if pattern.startswith("*."):
        # el comodin cubre una sola etiqueta
        return host.endswith(pattern[1:]) and "." not in host[: -len(pattern) + 1]
    return pattern.rstrip(".") == host


def _resolve_ips(engine: DnsEngine, host: str) -> list[str]:
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        q = engine.query(host, rtype)
        if q.status == OK:
            ips += q.records
    return ips


def _policy_check(engine, domain, mx, fetcher) -> dict:
    host = f"mta-sts.{domain}"
    ips = _resolve_ips(engine, host)
    if not ips:
        return {"status": "unreachable", "host": host, "error": "no A/AAAA record"}
    try:
        text = fetcher(host, ips)
    except PolicyError as exc:
        return {"status": "unreachable", "host": host, "error": str(exc)}
    policy, errors = parse_policy(text)
    if errors:
        return {"status": "invalid", "host": host, "policy": policy, "errors": errors}
    uncovered = []
    if policy["mode"] != "none":
        for rec in mx.records:
            target = rec.split()[-1]
            if not any(mx_matches(p, target) for p in policy["mx"]):
                uncovered.append(target.rstrip("."))
    return {
        "status": "ok",
        "host": host,
        "policy": policy,
        "uncovered_mx": uncovered,
        "errors": [],
    }


def receives_mail(mx: QueryResult) -> bool:
    # sin MX o con null MX el dominio no recibe correo y esto no aplica
    return mx.status == OK and mx.records != ["0 ."]


def audit_mta_sts(
    engine: DnsEngine, domain: str, mx: QueryResult, fetcher=None
) -> tuple[dict, list[Finding]]:
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

    policy = None
    if sts["status"] == "ok" and fetcher is not None:
        policy = _policy_check(engine, domain, mx, fetcher)
        findings += _policy_findings(policy)

    report = {"status": sts["status"], "mta_sts": sts, "tls_rpt": rpt, "note": NOTE}
    if policy:
        report["policy"] = policy
    return report, findings


def _policy_findings(p: dict) -> list[Finding]:
    out: list[Finding] = []
    if p["status"] == "unreachable":
        out.append(
            Finding(
                "MTASTS-003",
                Severity.MEDIUM,
                "MTA-STS policy file cannot be downloaded",
                "The record says MTA-STS is in use but senders cannot fetch the policy, so "
                "they cache nothing and the protection does not apply.",
                f"https://{p['host']}/.well-known/mta-sts.txt: {p['error']}",
                "Serve the policy over HTTPS with a valid certificate for the mta-sts host, "
                "status 200 and no redirects.",
                CATEGORY,
                "RFC 8461 section 3.3",
            )
        )
        return out
    if p["status"] == "invalid":
        out.append(
            Finding(
                "MTASTS-004",
                Severity.MEDIUM,
                "Invalid MTA-STS policy file",
                "Senders ignore a policy file that does not follow the format.",
                "\n".join(p["errors"]),
                "Fix the policy: version, mode, mx and max_age lines.",
                CATEGORY,
                "RFC 8461 section 3.2",
            )
        )
        return out
    pol = p["policy"]
    if p["uncovered_mx"]:
        enforce = pol["mode"] == "enforce"
        out.append(
            Finding(
                "MTASTS-005",
                Severity.HIGH if enforce else Severity.LOW,
                "MX hosts not covered by the MTA-STS policy",
                "Mail to these MX hosts "
                + ("is rejected by senders." if enforce else "would be rejected in enforce mode."),
                "Not matched by any mx line: " + ", ".join(p["uncovered_mx"]),
                "Add the MX hosts (or a *.domain pattern) to the policy.",
                CATEGORY,
                "RFC 8461 section 4.1",
            )
        )
    if pol["mode"] in ("testing", "none"):
        out.append(
            Finding(
                "MTASTS-006",
                Severity.LOW if pol["mode"] == "testing" else Severity.MEDIUM,
                f"MTA-STS mode is '{pol['mode']}'",
                "Senders do not refuse delivery when TLS fails, so the policy does not "
                "protect against downgrade attacks yet.",
                f"mode: {pol['mode']}",
                "Move to mode: enforce once TLS-RPT reports show no failures.",
                CATEGORY,
                "RFC 8461 section 5",
            )
        )
    if int(pol["max_age"]) < MIN_MAX_AGE:
        out.append(
            Finding(
                "MTASTS-007",
                Severity.LOW,
                "MTA-STS max_age is very short",
                "A short max_age lets the cached policy expire quickly, so an attacker only "
                "has to block the policy fetch for a short time.",
                f"max_age: {pol['max_age']}",
                "Use at least one week (604800) in enforce mode.",
                CATEGORY,
                "RFC 8461 section 3.2",
            )
        )
    return out
