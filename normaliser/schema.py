"""Common finding schema for cross-cloud compliance normalisation."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Provider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStatus(Enum):
    FAILED = "FAILED"
    PASSED = "PASSED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass
class FrameworkMapping:
    """A compliance framework requirement that a finding maps to."""
    name: str
    requirement_id: str
    strategy: Optional[str] = None
    maturity_level: Optional[int] = None


@dataclass
class Finding:
    """Normalised security finding from any cloud provider."""
    id: str
    provider: Provider
    source: str
    control_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_id: str
    region: str
    account_id: str
    compliance_status: ComplianceStatus
    first_seen: datetime
    last_seen: datetime
    frameworks: list[FrameworkMapping] = field(default_factory=list)
    remediation: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider.value,
            "source": self.source,
            "control_id": self.control_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "account_id": self.account_id,
            "compliance_status": self.compliance_status.value,
            "frameworks": [
                {
                    "name": f.name,
                    "requirement_id": f.requirement_id,
                    "strategy": f.strategy,
                    "maturity_level": f.maturity_level,
                }
                for f in self.frameworks
            ],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "remediation": self.remediation,
        }
