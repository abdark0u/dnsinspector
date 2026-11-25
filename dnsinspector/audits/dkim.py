"""Auditoria DKIM: solo mira el registro de clave publica, no verifica firmas."""

import base64
import binascii

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from dnsinspector.audits import parse_tag_list
from dnsinspector.dns_engine import NODATA, NXDOMAIN, OK, DnsEngine
from dnsinspector.findings import Finding, Severity

REF = "RFC 6376 section 3.6.1"
CATEGORY = "Email security / DKIM"
# selectores comunes de los proveedores mas usados (maximo 10 consultas)
COMMON_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
]
NOTE = (
    "Only the public key record is checked. A valid DKIM signature can only be confirmed by "
    "verifying a real signed message."
)


def check_key_record(record: str) -> dict:
    """Analiza un registro de clave DKIM. Devuelve tags, errores, tipo y bits de la clave."""
    tags, errors = parse_tag_list(record)
    info: dict = {"tags": tags, "errors": errors, "key_type": None, "key_bits": None}
    if "v" in tags and (tags["v"] != "DKIM1" or not record.strip().startswith("v=")):
        errors.append("'v' must be 'DKIM1' and be the first tag")
    key_type = tags.get("k", "rsa").lower()
    info["key_type"] = key_type
    if key_type not in ("rsa", "ed25519"):
        errors.append(f"Unknown key type k={key_type}")
    if "p" not in tags:
        errors.append("Missing required public key tag 'p'")
        return info
    if tags["p"] == "":
        info["revoked"] = True
        return info
    try:
        key_bytes = base64.b64decode("".join(tags["p"].split()), validate=True)
    except (binascii.Error, ValueError):
        errors.append("Public key 'p' is not valid base64")
        return info
    if key_type == "ed25519":
        if len(key_bytes) != 32:
            errors.append("Ed25519 key must be 32 bytes")
        info["key_bits"] = 256
    elif key_type == "rsa":
        try:
            key = load_der_public_key(key_bytes)
        except ValueError:
            errors.append("Public key 'p' is not a valid RSA key")
            return info
        if not isinstance(key, rsa.RSAPublicKey):
            errors.append("Key type is rsa but 'p' is not an RSA key")
            return info
        info["key_bits"] = key.key_size
    return info


def audit_dkim(
    engine: DnsEngine, domain: str, selectors: list[str], probe: bool = False
) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    if not selectors and not probe:
        findings.append(
            Finding(
                "DKIM-001",
                Severity.INFO,
                "DKIM not checked (no selector given)",
                "DKIM keys live at <selector>._domainkey.<domain> and selectors cannot be listed "
                "through DNS.",
                "No selector provided",
                "Find the selector in the 'DKIM-Signature: s=' header of a sent email and run "
                "the analysis again with it.",
                CATEGORY,
                REF,
            )
        )
        return {"status": "not_checked", "selectors": [], "note": NOTE}, findings

    results = []
    # los selectores probados solo se muestran si existen (un fallo no es un hallazgo)
    probed = [s for s in COMMON_SELECTORS if s not in selectors] if probe else []
    for selector in [*selectors, *probed]:
        is_probe = selector in probed
        name = f"{selector}._domainkey.{domain}"
        query = engine.query(name, "TXT")
        entry: dict = {"selector": selector, "name": name, "dns_status": query.status}
        if is_probe:
            entry["probed"] = True
        if is_probe and not any("p=" in r or r.startswith("v=DKIM1") for r in query.records):
            continue
        results.append(entry)
        if query.status not in (OK, NODATA, NXDOMAIN):
            entry["status"] = "error"
            continue
        # algunos proveedores ponen un CNAME, el resolver ya lo sigue
        keys = [r for r in query.records if "p=" in r or r.startswith("v=DKIM1")]
        if not keys:
            entry["status"] = "missing"
            findings.append(
                Finding(
                    "DKIM-002",
                    Severity.MEDIUM,
                    f"No DKIM key for selector '{selector}'",
                    "Mail signed with this selector will fail DKIM verification.",
                    f"TXT {name}: {query.status}",
                    "Check the selector name or publish the key from your mail provider.",
                    CATEGORY,
                    REF,
                )
            )
            continue
        entry["record"] = keys[0]
        entry.update(check_key_record(keys[0]))
        entry["status"] = _key_findings(entry, findings)
    if probe and not results:
        findings.append(
            Finding(
                "DKIM-008",
                Severity.INFO,
                "No DKIM key found among common selectors",
                f"{len(probed)} common selectors were probed and none has a key record. The "
                "domain may use a custom selector.",
                "Probed: " + ", ".join(probed),
                "Find the selector in the 'DKIM-Signature: s=' header of a sent email.",
                CATEGORY,
                REF,
            )
        )
        return {"status": "not_found", "selectors": [], "probed": probed, "note": NOTE}, findings
    statuses = {r["status"] for r in results}
    overall = next(
        (s for s in ("invalid", "missing", "error", "weak", "revoked") if s in statuses), "ok"
    )
    out = {"status": overall, "selectors": results, "note": NOTE}
    if probe:
        out["probed"] = probed
    return out, findings


def _key_findings(entry: dict, findings: list[Finding]) -> str:
    selector, record = entry["selector"], entry["record"]
    if entry["errors"]:
        findings.append(
            Finding(
                "DKIM-003",
                Severity.HIGH,
                f"Invalid DKIM key record for '{selector}'",
                "Receivers cannot use a malformed key, so signatures will fail.",
                record + "\n" + "\n".join(entry["errors"]),
                "Republish the key record.",
                CATEGORY,
                REF,
            )
        )
        return "invalid"
    if entry.get("revoked"):
        findings.append(
            Finding(
                "DKIM-004",
                Severity.INFO,
                f"DKIM key for '{selector}' is revoked",
                "An empty 'p=' means the key was intentionally revoked.",
                record,
                "Make sure no mail is still signed with this selector.",
                CATEGORY,
                REF,
            )
        )
        return "revoked"
    status = "ok"
    bits = entry["key_bits"]
    if entry["key_type"] == "rsa" and bits and bits < 1024:
        findings.append(
            Finding(
                "DKIM-005",
                Severity.HIGH,
                f"DKIM RSA key for '{selector}' is too short",
                "Verifiers must not accept RSA keys under 1024 bits; they can be factored.",
                f"{bits}-bit RSA key",
                "Rotate to a 2048-bit RSA key.",
                CATEGORY,
                "RFC 8301",
            )
        )
        status = "weak"
    elif entry["key_type"] == "rsa" and bits and bits < 2048:
        findings.append(
            Finding(
                "DKIM-006",
                Severity.LOW,
                f"DKIM RSA key for '{selector}' is under 2048 bits",
                "1024-bit keys are still accepted but RFC 8301 recommends 2048 bits.",
                f"{bits}-bit RSA key",
                "Rotate to a 2048-bit RSA key.",
                CATEGORY,
                "RFC 8301",
            )
        )
    if "y" in entry["tags"].get("t", "").split(":"):
        findings.append(
            Finding(
                "DKIM-007",
                Severity.LOW,
                f"DKIM selector '{selector}' is in test mode (t=y)",
                "Receivers may treat signed and unsigned mail the same while t=y is set.",
                record,
                "Remove 't=y' once DKIM works.",
                CATEGORY,
                REF,
            )
        )
    return status
