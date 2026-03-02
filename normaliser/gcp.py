"""Normalise GCP Security Command Center findings to common schema."""

from datetime import datetime

from .schema import ComplianceStatus, Finding, Provider, Severity


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def normalise_scc_finding(raw: dict) -> Finding:
    """Convert a SCC finding to the common schema."""
    finding_data = raw.get("finding", raw)
    resource = raw.get("resource", {})

    severity_str = finding_data.get("severity", "LOW")
    state = finding_data.get("state", "ACTIVE")

    return Finding(
        id=finding_data.get("name", ""),
        provider=Provider.GCP,
        source="scc",
        control_id=finding_data.get("category", ""),
        title=finding_data.get("category", ""),
        severity=SEVERITY_MAP.get(severity_str, Severity.LOW),
        resource_type=resource.get("type", "Unknown"),
        resource_id=resource.get("name", ""),
        region=_extract_region(resource),
        account_id=resource.get("project", ""),
        compliance_status=_map_state(state),
        first_seen=_parse_timestamp(finding_data.get("createTime", "")),
        last_seen=_parse_timestamp(finding_data.get("eventTime", "")),
        remediation=finding_data.get("externalUri"),
    )


def _extract_region(resource: dict) -> str:
    """Extract region from SCC resource location."""
    folders = resource.get("folders", [])
    location = resource.get("location", "")
    if location:
        return location
    return "global"


def _map_state(state: str) -> ComplianceStatus:
    mapping = {
        "ACTIVE": ComplianceStatus.FAILED,
        "INACTIVE": ComplianceStatus.PASSED,
    }
    return mapping.get(state, ComplianceStatus.NOT_AVAILABLE)


def _parse_timestamp(ts: str) -> datetime:
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min
