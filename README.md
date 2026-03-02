# cross-cloud-compliance

Normalise security findings from multiple cloud providers into a single compliance view against Australian frameworks.

## Problem

Organisations running workloads across AWS, GCP, and Azure get security findings in three different formats, three different severity scales, and three different consoles. Mapping those findings to compliance obligations (Essential Eight, ISM, CIS Benchmarks, RFFR) is manual, error-prone, and typically done in spreadsheets once a quarter.

This project replaces that with continuous, automated compliance posture reporting.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Data Sources                      │
├─────────────────┬─────────────────┬─────────────────┤
│  AWS Security   │   GCP Security  │     Azure       │
│      Hub        │ Command Center  │    Defender     │
└────────┬────────┴────────┬────────┴────────┬────────┘
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────┐
│              Normalisation Layer                     │
│                                                     │
│  - Common finding schema (provider, control, sev)   │
│  - Deduplicate cross-provider findings              │
│  - Enrich with resource metadata                    │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│            Framework Mapping Engine                  │
│                                                     │
│  Finding control ID  ──►  Framework requirement     │
│                                                     │
│  Supported frameworks:                              │
│  - ACSC Essential Eight (maturity levels 1-3)       │
│  - ISM (Information Security Manual)                │
│  - CIS Benchmarks (AWS, GCP, Azure)                │
│  - RFFR (Registrar Financial Fitness Rules)         │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                    Outputs                           │
├─────────────────┬─────────────────┬─────────────────┤
│  E8 Maturity    │    Executive    │  Remediation    │
│     View        │   Dashboard    │    Backlog      │
└─────────────────┴─────────────────┴─────────────────┘
```

## Framework Mappings

The mapping engine translates cloud-native security controls to compliance framework requirements.

### Essential Eight Coverage

| E8 Strategy | AWS Security Hub | GCP SCC | Azure Defender |
|---|---|---|---|
| Application Control | FSBP EC2.18, Lambda.1 | SCC container-threat | Defender app control alerts |
| Patch Applications | FSBP SSM.1, SSM.2 | SCC OS vulnerability | Defender vulnerability assessment |
| Configure MS Office Macros | N/A (non-cloud) | N/A | Defender for Endpoint |
| User Application Hardening | FSBP EC2.8, CloudFront.* | SCC web security scanner | Defender for App Service |
| Restrict Admin Privileges | FSBP IAM.1-6, IAM.8 | SCC IAM findings | Defender identity alerts |
| Patch OS | FSBP SSM.1, Inspector findings | SCC OS vulnerability | Defender for Servers |
| Multi-Factor Authentication | FSBP IAM.5, CIS 1.10-1.14 | SCC MFA findings | Defender identity MFA |
| Regular Backups | FSBP RDS.*, S3.*, DynamoDB.* | SCC storage findings | Defender storage alerts |

### Finding Schema

```json
{
  "id": "string",
  "provider": "aws | gcp | azure",
  "source": "securityhub | scc | defender",
  "control_id": "string",
  "title": "string",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "resource_type": "string",
  "resource_id": "string",
  "region": "string",
  "account_id": "string",
  "compliance_status": "FAILED | PASSED | NOT_AVAILABLE",
  "frameworks": [
    {
      "name": "essential-eight",
      "strategy": "patch-os",
      "maturity_level": 1,
      "requirement_id": "E8-6.1"
    }
  ],
  "first_seen": "ISO8601",
  "last_seen": "ISO8601",
  "remediation": "string"
}
```

## Project Structure

```
├── mappings/
│   ├── aws_securityhub.yaml      # Security Hub control → framework mapping
│   ├── gcp_scc.yaml              # SCC finding type → framework mapping
│   ├── azure_defender.yaml       # Defender alert → framework mapping
│   └── frameworks/
│       ├── essential_eight.yaml  # E8 strategies and maturity criteria
│       ├── ism.yaml              # ISM control definitions
│       └── cis.yaml              # CIS benchmark controls
├── normaliser/
│   ├── schema.py                 # Common finding schema
│   ├── aws.py                    # Security Hub → common schema
│   ├── gcp.py                    # SCC → common schema
│   └── azure.py                  # Defender → common schema
├── engine/
│   ├── mapper.py                 # Finding → framework requirement mapping
│   └── scorer.py                 # Maturity/compliance scoring
├── outputs/
│   ├── dashboard.py              # Executive summary generation
│   └── backlog.py                # Remediation item generation
└── tests/
    ├── test_normaliser.py
    ├── test_mapper.py
    └── fixtures/                 # Sample findings from each provider
```

## Status

Work in progress. Mapping definitions and normalisation layer under active development.

## License

MIT
