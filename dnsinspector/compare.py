"""Compara dos analisis del mismo dominio."""

AUDITS = ("spf", "dkim", "dmarc", "dnssec")


def compare_reports(first: dict, second: dict) -> dict:
    """Devuelve que ha cambiado del analisis mas antiguo al mas nuevo."""
    if first["domain"] != second["domain"]:
        raise ValueError("Only analyses of the same domain can be compared")
    old, new = sorted((first, second), key=lambda r: (r["started_at"], r.get("id", 0)))

    records = {}
    for rtype in new["records"]:
        before = set(old["records"].get(rtype, {}).get("records", []))
        after = set(new["records"][rtype]["records"])
        records[rtype] = {
            "added": sorted(after - before),
            "removed": sorted(before - after),
            "unchanged": sorted(before & after),
        }

    statuses = {
        key: {
            "before": old.get(key, {}).get("status"),
            "after": new.get(key, {}).get("status"),
        }
        for key in AUDITS
    }
    for value in statuses.values():
        value["changed"] = value["before"] != value["after"]

    old_findings = {f["id"]: f for f in old["findings"]}
    new_findings = {f["id"]: f for f in new["findings"]}
    return {
        "domain": new["domain"],
        "before": {"id": old.get("id"), "started_at": old["started_at"], "summary": old["summary"]},
        "after": {"id": new.get("id"), "started_at": new["started_at"], "summary": new["summary"]},
        "records": records,
        "statuses": statuses,
        "findings": {
            "new": [new_findings[i] for i in new_findings if i not in old_findings],
            "resolved": [old_findings[i] for i in old_findings if i not in new_findings],
            "unchanged": [new_findings[i] for i in new_findings if i in old_findings],
        },
    }
