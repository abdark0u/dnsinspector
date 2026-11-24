"""Comprueba cada servidor autoritativo del dominio (lame delegation y serial del SOA)."""

import ipaddress

from dnsinspector.dns_engine import OK, DnsEngine, QueryResult
from dnsinspector.findings import Finding, Severity

CATEGORY = "DNS configuration"
# limites para no hacer demasiadas consultas
MAX_NS = 6
MAX_IPS_PER_NS = 2


def _servers(engine: DnsEngine, domain: str, ns_names: list[str]) -> list[dict]:
    servers: list[dict] = []
    for ns in ns_names[:MAX_NS]:
        host = ns.rstrip(".")
        # miramos IPv4 y IPv6 (maximo MAX_IPS_PER_NS de cada)
        v4 = engine.query(host, "A")
        v6 = engine.query(host, "AAAA")
        ips = (v4.records[:MAX_IPS_PER_NS] if v4.status == OK else []) + (
            v6.records[:MAX_IPS_PER_NS] if v6.status == OK else []
        )
        if not ips:
            servers.append(
                {
                    "ns": host,
                    "ip": None,
                    "status": "unresolved",
                    "error": f"A {host}: {v4.status}, AAAA {host}: {v6.status}",
                }
            )
            continue
        for ip in ips:
            if not ipaddress.ip_address(ip).is_global:
                # no mandamos consultas a redes privadas
                servers.append(
                    {"ns": host, "ip": ip, "status": "not_checked", "error": "non-public address"}
                )
                continue
            result = engine.query_authoritative(ip, domain)
            if ":" in ip and result["status"] == "error":
                # sin ruta IPv6 desde este equipo no es culpa del servidor
                result = {
                    **result,
                    "status": "not_checked",
                    "error": f"IPv6 unreachable: {result['error']}",
                }
            servers.append({"ns": host, "ip": ip, **result})
    return servers


def audit_nameservers(
    engine: DnsEngine, domain: str, ns_result: QueryResult
) -> tuple[dict, list[Finding]]:
    if ns_result.status != OK:
        return {"status": "skipped", "servers": []}, []

    servers = _servers(engine, domain, ns_result.records)
    findings: list[Finding] = []
    lame = [s for s in servers if s["status"] in ("lame", "unresolved")]
    down = [s for s in servers if s["status"] in ("timeout", "error")]
    # cada proveedor DNS tiene su propio serial, asi que comparamos por servidor primario (MNAME)
    by_primary: dict[str, set[int]] = {}
    for server in servers:
        if server["status"] == OK:
            by_primary.setdefault(server["primary"], set()).add(server["serial"])
    mismatch = any(len(serials) > 1 for serials in by_primary.values())

    if lame:
        findings.append(
            Finding(
                "DNS-006",
                Severity.MEDIUM,
                "Lame delegation",
                "These name servers are listed for the domain but do not answer "
                "authoritatively for it, so resolvers that pick them get errors or delays.",
                "\n".join(_line(s) for s in lame),
                "Remove them from the NS records (at the registrar and in the zone) or "
                "configure the zone on them.",
                CATEGORY,
                "RFC 1034 section 4.2.2",
            )
        )
    if down:
        findings.append(
            Finding(
                "DNS-007",
                Severity.MEDIUM,
                "Name server not responding",
                "These name servers did not answer the SOA query, which slows down or breaks "
                "resolution when resolvers pick them.",
                "\n".join(_line(s) for s in down),
                "Check that the servers are up and that UDP/TCP port 53 is reachable.",
                CATEGORY,
                "RFC 1034 section 4.2.2",
            )
        )
    if mismatch:
        findings.append(
            Finding(
                "DNS-008",
                Severity.LOW,
                "SOA serial differs between name servers",
                "The name servers are serving different versions of the zone. This is normal "
                "for a few minutes after a change; if it lasts, zone transfers are failing.",
                "\n".join(_line(s) for s in servers if s["status"] == OK),
                "Check zone transfers (NOTIFY/AXFR/IXFR) between primary and secondaries.",
                CATEGORY,
                "RFC 1996",
            )
        )

    if lame or down:
        status = "lame" if lame else "unreachable"
    elif mismatch:
        status = "inconsistent"
    elif by_primary:
        status = "ok"
    else:
        status = "not_checked"
    return {"status": status, "servers": servers}, findings


def _line(server: dict) -> str:
    detail = server.get("error") or ""
    if server.get("serial") is not None:
        detail = f"serial {server['serial']} (primary {server['primary']})"
    elif server.get("rcode"):
        detail = f"rcode {server['rcode']}, AA={int(server['aa'])}"
    return f"{server['ns']} ({server['ip'] or '-'}): {server['status']} {detail}".strip()
