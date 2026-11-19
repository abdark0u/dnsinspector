"""Motor DNS: hace una consulta y clasifica el resultado."""

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename

from dnsinspector.config import Settings

logger = logging.getLogger(__name__)

LOOKUP_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]

# estados posibles de una consulta
OK, NODATA, NXDOMAIN, TIMEOUT, ERROR = "ok", "nodata", "nxdomain", "timeout", "error"


@dataclass
class QueryResult:
    name: str
    rtype: str
    status: str
    records: list[str] = field(default_factory=list)
    ttl: int | None = None
    nameserver: str | None = None
    elapsed_ms: float = 0.0
    ad_flag: bool = False
    error: str | None = None
    # datos crudos para DNSSEC, no se guardan en el JSON
    rrset: Any = field(default=None, repr=False)
    rrsigs: list[Any] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("rrset")
        data.pop("rrsigs")
        return data


def _rdata_to_text(rdata: Any) -> str:
    # los TXT vienen troceados en strings de 255, aqui los juntamos
    if rdata.rdtype == dns.rdatatype.TXT:
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return rdata.to_text()


def _sort_key(rdata: Any) -> tuple:
    # MX por prioridad, el resto alfabetico
    if rdata.rdtype == dns.rdatatype.MX:
        return (rdata.preference, rdata.exchange.to_text())
    return (0, _rdata_to_text(rdata))


class DnsEngine:
    """Envoltorio de dnspython con tiempos de espera limitados."""

    def __init__(
        self, settings: Settings | None = None, resolver: Any = None, send: Any = None
    ) -> None:
        settings = settings or Settings()
        self.timeout = settings.dns_timeout
        # funcion que manda una consulta directa a un servidor (en los tests se cambia)
        self.send = send or dns.query.udp
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=not settings.nameservers)
            if settings.nameservers:
                resolver.nameservers = settings.nameservers
            resolver.timeout = settings.dns_timeout
            resolver.lifetime = settings.dns_timeout
            # pedimos los RRSIG (bit DO) para poder mirar DNSSEC
            resolver.use_edns(0, dns.flags.DO, 1232)
        self.resolver = resolver

    @property
    def nameservers(self) -> list[str]:
        return [str(ns) for ns in self.resolver.nameservers]

    def query(self, name: str, rtype: str) -> QueryResult:
        """Hace una consulta y nunca lanza excepcion: el fallo va en el campo status."""
        result = QueryResult(name=name, rtype=rtype, status=ERROR)
        start = time.perf_counter()
        try:
            answer = self.resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            result.status = NXDOMAIN
        except dns.exception.Timeout:
            result.status = TIMEOUT
            result.error = "DNS query timed out"
        except dns.resolver.NoNameservers as exc:
            result.error = f"No nameserver could answer (SERVFAIL/REFUSED): {exc}"
        except dns.exception.DNSException as exc:
            result.error = str(exc) or exc.__class__.__name__
        else:
            self._fill_from_answer(result, answer)
        result.elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        logger.debug("query %s %s -> %s", name, rtype, result.status)
        return result

    def query_authoritative(self, ip: str, name: str) -> dict:
        """Pregunta el SOA directamente a un servidor autoritativo (sin recursion)."""
        query = dns.message.make_query(name, "SOA")
        query.flags &= ~dns.flags.RD
        result: dict = {"status": ERROR, "serial": None, "aa": False, "rcode": None, "error": None}
        start = time.perf_counter()
        try:
            response = self.send(query, ip, timeout=self.timeout)
        except dns.exception.Timeout:
            result["status"] = TIMEOUT
        except (OSError, dns.exception.DNSException) as exc:
            result["error"] = str(exc) or exc.__class__.__name__
        else:
            result["rcode"] = dns.rcode.to_text(response.rcode())
            result["aa"] = bool(response.flags & dns.flags.AA)
            soa = next((r for r in response.answer if r.rdtype == dns.rdatatype.SOA), None)
            # si no es AA o no trae el SOA, el servidor no sirve la zona (lame)
            if result["rcode"] == "NOERROR" and result["aa"] and soa:
                result["status"] = OK
                result["serial"] = soa[0].serial
                result["primary"] = soa[0].mname.to_text()
            else:
                result["status"] = "lame"
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 1)
        return result

    def reverse(self, ip: str) -> QueryResult:
        """Consulta PTR de una IP."""
        result = self.query(dns.reversename.from_address(ip).to_text(), "PTR")
        result.name = ip
        return result

    @staticmethod
    def _fill_from_answer(result: QueryResult, answer: Any) -> None:
        result.nameserver = getattr(answer, "nameserver", None)
        response = answer.response
        result.ad_flag = bool(response.flags & dns.flags.AD)
        rdtype = dns.rdatatype.from_text(result.rtype)
        if answer.rrset is None:
            result.status = NODATA
            return
        result.status = OK
        result.rrset = answer.rrset
        result.ttl = answer.rrset.ttl
        result.records = [_rdata_to_text(r) for r in sorted(answer.rrset, key=_sort_key)]
        result.rrsigs = [
            rrset
            for rrset in response.answer
            if rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers == rdtype
        ]
