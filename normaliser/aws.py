"""Normalise AWS Security Hub findings to common schema."""

from datetime import datetime

from .schema import ComplianceStatus, Finding, Provider, Severity


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
}


def normalise_securityhub_finding(raw: dict) -> Finding:
    """Convert a Security Hub ASFF finding to the common schema."""
    severity_label = raw.get("Severity", {}).get("Label", "INFORMATIONAL")
    compliance = raw.get("Compliance", {}).get("Status", "NOT_AVAILABLE")

    resources = raw.get("Resources", [{}])
    resource = resources[0] if resources else {}

    return Finding(
        id=raw["Id"],
        provider=Provider.AWS,
        source="securityhub",
        control_id=_extract_control_id(raw),
        title=raw.get("Title", ""),
        severity=SEVERITY_MAP.get(severity_label, Severity.INFO),
        resource_type=resource.get("Type", "Unknown"),
        resource_id=resource.get("Id", ""),
        region=raw.get("Region", ""),
        account_id=raw.get("AwsAccountId", ""),
        compliance_status=_map_compliance_status(compliance),
        first_seen=_parse_timestamp(raw.get("FirstObservedAt", "")),
        last_seen=_parse_timestamp(raw.get("LastObservedAt", "")),
        remediation=raw.get("Remediation", {}).get("Recommendation", {}).get("Text"),
    )


def _extract_control_id(finding: dict) -> str:
    """Extract the control ID from a Security Hub finding."""
    generator = finding.get("GeneratorId", "")
    if "/" in generator:
        return generator.rsplit("/", 1)[-1]
    return generator


def _map_compliance_status(status: str) -> ComplianceStatus:
    mapping = {
        "PASSED": ComplianceStatus.PASSED,
        "FAILED": ComplianceStatus.FAILED,
        "WARNING": ComplianceStatus.FAILED,
        "NOT_AVAILABLE": ComplianceStatus.NOT_AVAILABLE,
    }
    return mapping.get(status, ComplianceStatus.NOT_AVAILABLE)


def _parse_timestamp(ts: str) -> datetime:
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min
