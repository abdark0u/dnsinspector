"""Modelo de hallazgos (findings) y niveles de severidad."""

from dataclasses import asdict, dataclass
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# orden de mas grave a menos grave
SEVERITY_ORDER = list(Severity)


@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    category: str
    reference: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))


def summarize(findings: list[Finding]) -> dict:
    """Cuenta hallazgos por severidad y dice cual es la mas alta."""
    counts = {sev.value: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.value] += 1
    highest = next((sev.value for sev in SEVERITY_ORDER if counts[sev.value]), None)
    return {"counts": counts, "total": len(findings), "highest_severity": highest}
