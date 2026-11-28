"""Configuracion leida de variables de entorno."""

import os
from dataclasses import dataclass, field
from pathlib import Path


def _list_env(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # si esta vacio se usan los DNS del sistema (/etc/resolv.conf)
    nameservers: list[str] = field(default_factory=lambda: _list_env("DNS_NAMESERVERS"))
    dns_timeout: float = field(default_factory=lambda: float(os.getenv("DNS_TIMEOUT", "3")))
    database_path: Path = field(
        default_factory=lambda: Path(os.getenv("DATABASE_PATH", "data/dnsinspector.db"))
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
    )
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").upper())
    # si esta vacio la API es abierta (comportamiento de siempre)
    api_token: str = field(default_factory=lambda: os.getenv("DNSINSPECTOR_TOKEN", ""))
