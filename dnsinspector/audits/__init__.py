"""Auditorias de seguridad. Cada una devuelve (estado, lista de hallazgos)."""


def parse_tag_list(record: str) -> tuple[dict[str, str], list[str]]:
    """Parte 'v=DKIM1; k=rsa; p=...' en un dict. Lo usan DKIM y DMARC."""
    tags: dict[str, str] = {}
    errors: list[str] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"Tag without '=': '{part}'")
            continue
        key, value = (x.strip() for x in part.split("=", 1))
        key = key.lower()
        if key in tags:
            errors.append(f"Duplicate tag '{key}'")
        tags[key] = value
    return tags, errors
