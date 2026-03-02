"""Map normalised findings to compliance framework requirements."""

from pathlib import Path

import yaml

from normaliser.schema import Finding, FrameworkMapping


MAPPINGS_DIR = Path(__file__).parent.parent / "mappings"


def load_provider_mappings(provider: str) -> dict:
    """Load the control-to-framework mapping for a cloud provider."""
    mapping_files = {
        "aws": "aws_securityhub.yaml",
        "gcp": "gcp_scc.yaml",
        "azure": "azure_defender.yaml",
    }
    path = MAPPINGS_DIR / mapping_files[provider]
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f)


def map_finding(finding: Finding) -> Finding:
    """Enrich a finding with compliance framework mappings."""
    mappings = load_provider_mappings(finding.provider.value)
    control_key = finding.control_id

    if finding.provider.value == "aws":
        controls = mappings.get("controls", {})
        control = controls.get(control_key, {})
    elif finding.provider.value == "gcp":
        controls = mappings.get("finding_categories", {})
        control = controls.get(control_key, {})
    else:
        control = {}

    if control:
        e8_strategy = control.get("e8_strategy")
        e8_maturity = control.get("e8_maturity")
        if e8_strategy:
            finding.frameworks.append(
                FrameworkMapping(
                    name="essential-eight",
                    requirement_id=f"E8-{e8_strategy}-ML{e8_maturity}",
                    strategy=e8_strategy,
                    maturity_level=e8_maturity,
                )
            )

        cis_id = control.get("cis")
        if cis_id:
            finding.frameworks.append(
                FrameworkMapping(
                    name=f"cis-{finding.provider.value}",
                    requirement_id=cis_id,
                )
            )

    return finding


def score_e8_maturity(findings: list[Finding]) -> dict:
    """Calculate Essential Eight maturity level per strategy based on findings."""
    strategies = {}
    for finding in findings:
        for fw in finding.frameworks:
            if fw.name != "essential-eight" or not fw.strategy:
                continue
            if fw.strategy not in strategies:
                strategies[fw.strategy] = {"total": 0, "failed": 0, "max_maturity": 0}
            strategies[fw.strategy]["total"] += 1
            strategies[fw.strategy]["max_maturity"] = max(
                strategies[fw.strategy]["max_maturity"], fw.maturity_level or 0
            )
            if finding.compliance_status.value == "FAILED":
                strategies[fw.strategy]["failed"] += 1

    result = {}
    for strategy, counts in strategies.items():
        pass_rate = 1 - (counts["failed"] / counts["total"]) if counts["total"] > 0 else 0
        result[strategy] = {
            "total_controls": counts["total"],
            "failed_controls": counts["failed"],
            "pass_rate": round(pass_rate * 100, 1),
            "assessed_maturity": counts["max_maturity"],
        }

    return result
