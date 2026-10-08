from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(Enum):
    HIGH = "alta"
    MEDIUM = "média"
    LOW = "baixa"


@dataclass
class Finding:
    """Uma vulnerabilidade ou problema encontrado."""
    module: str
    title: str
    severity: Severity
    description: str
    recommendation: str = ""


@dataclass
class ScanResult:
    """Resultado consolidado de uma varredura."""
    target: str
    started_at: datetime = field(default_factory=datetime.now)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts