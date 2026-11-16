"""Validacion de lo que mete el usuario (dominios, selectores e IPs)."""

import ipaddress
import re

# solo letras, numeros y guiones, sin guion al principio ni al final
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SELECTOR_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")

# TLDs internos o reservados, no tiene sentido mirarlos en DNS publico
_BLOCKED_TLDS = {"localhost", "local", "internal", "lan", "home", "invalid", "corp", "intranet"}


class ValidationError(ValueError):
    """Entrada no valida."""


def normalize_domain(value: str) -> str:
    """Limpia y valida un dominio. Devuelve el dominio en minusculas y en ASCII (punycode)."""
    domain = (value or "").strip().lower().rstrip(".")
    if not domain:
        raise ValidationError("Domain is required")
    if "://" in domain or "/" in domain or "@" in domain or " " in domain:
        raise ValidationError("Enter only the domain name, e.g. example.com")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("Invalid internationalized domain name") from exc
    if len(domain) > 253:
        raise ValidationError("Domain is longer than 253 characters")

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValidationError("Domain must have at least two labels, e.g. example.com")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError(f"Invalid label in domain: '{label}'")
    if labels[-1].isdigit():
        raise ValidationError("Top-level domain cannot be numeric (IP addresses are not domains)")
    if labels[-1] in _BLOCKED_TLDS or domain.endswith("home.arpa"):
        raise ValidationError("Private or reserved domains are not allowed")
    return domain


def normalize_selector(value: str) -> str:
    """Valida un selector DKIM (puede tener puntos, ej: s1.mail)."""
    selector = (value or "").strip().lower().rstrip(".")
    if not selector or len(selector) > 128:
        raise ValidationError("DKIM selector must be 1-128 characters")
    for label in selector.split("."):
        if not _SELECTOR_LABEL_RE.match(label):
            raise ValidationError(f"Invalid DKIM selector: '{selector}'")
    return selector


def parse_public_ip(value: str) -> str | None:
    """Devuelve la IP si es una IP publica, None si no es una IP. Error si es privada."""
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    if not ip.is_global:
        raise ValidationError("Only public IP addresses can be looked up")
    return str(ip)
