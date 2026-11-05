from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_LABEL_ZH = {
    "info": "信息",
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get((value or "info").lower(), 0)


def max_severity(values) -> str:
    best = "info"
    for value in values:
        if severity_rank(value) > severity_rank(best):
            best = (value or "info").lower()
    return best


@dataclass
class Finding:
    """A single, explainable observation.

    Findings are deliberately conservative: a finding means "this deserves a
    look", not "this is malware".  Every finding carries evidence and a source
    so the report can be reviewed without rerunning the scanner.
    """

    title: str
    severity: str
    category: str
    detail: str = ""
    path: str = ""
    source: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def __post_init__(self) -> None:
        self.severity = (self.severity or "info").lower()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "severity_label": SEVERITY_LABEL_ZH.get(self.severity, self.severity),
            "category": self.category,
            "detail": self.detail,
            "path": self.path,
            "source": self.source,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
