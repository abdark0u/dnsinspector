"""Resolver falso para que los tests no dependan de Internet."""

from dataclasses import dataclass, field
from typing import Any

import dns.flags
import dns.name
import dns.resolver
import dns.rrset


@dataclass
class FakeResponse:
    flags: int = 0
    answer: list[Any] = field(default_factory=list)
    authority: list[Any] = field(default_factory=list)


@dataclass
class FakeAnswer:
    rrset: Any
    response: FakeResponse
    nameserver: str = "192.0.2.53"


class FakeResolver:
    """Mapa (nombre, tipo) -> lista de valores, excepcion o rrsets ya hechos."""

    def __init__(self, data: dict | None = None, ad: bool = False) -> None:
        self.data = {(k[0].rstrip(".").lower(), k[1]): v for k, v in (data or {}).items()}
        self.ad = ad
        self.nameservers = ["192.0.2.53"]
        self.calls: list[tuple[str, str]] = []
        self.denial: list[Any] = []  # NSEC/NSEC3 que devuelve un nombre aleatorio inexistente

    def resolve(self, name: Any, rtype: str, raise_on_no_answer: bool = True) -> FakeAnswer:
        key = (str(name).rstrip(".").lower(), rtype)
        self.calls.append(key)
        flags = dns.flags.QR | (dns.flags.AD if self.ad else 0)
        value = self.data.get(key)
        if key[0].startswith("_dnsinspector-"):
            qname = dns.name.from_text(key[0])
            response = FakeResponse(flags, authority=self.denial)
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response})
        if isinstance(value, Exception):
            raise value
        if isinstance(value, type) and issubclass(value, Exception):
            raise value()
        if value is None:
            # el nombre existe si tiene algun otro tipo, si no NXDOMAIN
            if any(k[0] == key[0] for k in self.data):
                return FakeAnswer(rrset=None, response=FakeResponse(flags))

            raise dns.resolver.NXDOMAIN()
        if isinstance(value, tuple):  # (rrset, [rrsigs]) para DNSSEC
            rrset, sigs = value
            return FakeAnswer(rrset=rrset, response=FakeResponse(flags, [rrset, *sigs]))
        rrset = dns.rrset.from_text_list(dns.name.from_text(key[0]), 300, "IN", rtype, value)
        return FakeAnswer(rrset=rrset, response=FakeResponse(flags, [rrset]))
