# Changelog - aws-compliance-baseline-terraform

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-08-13

### Added

- Initial control baseline: preventive guardrails, detective/CSPM configuration,
  centralized audit logging, encryption, and network posture modules.
- `controls/controls.yaml` as the single machine-readable source of truth, with
  `controls/render.py` generating `CONTROLS.md` and verifying every claimed
  control resolves to a real Terraform address.
- CI: `terraform fmt`/`validate`, tflint, Checkov, Trivy, Conftest, gitleaks and
  control-matrix integrity checks.
- `examples/org-wide/` and `examples/single-account/` deployment shapes.
- FedRAMP baseline selectable between Moderate and High via variable.

### AWS specifics in this release

- Five themed service control policies (identity, audit, data, region, compute)
  plus two resource control policies, attached to configurable OU or root
  targets within the five-policies-per-target Organizations quota.
- Organization CloudTrail with log file validation and a KMS CMK, delivering to
  a central S3 archive with Object Lock in COMPLIANCE mode, versioning, TLS-only
  and tamper-deny bucket policies, lifecycle tiering and - at the High baseline -
  cross-region replication with a 15-minute SLA and its own Object Lock.
- All fifteen CIS AWS Foundations v5.0 section-4 metric filters and alarms,
  generated from a single table, plus an alarm on trail delivery stopping.
- Security Hub with delegated administration, organization auto-enable and the
  CIS v5.0, NIST SP 800-53 Rev 5 and FSBP standards; AWS Config organization
  recorder, aggregator and three conformance packs; GuardDuty with S3, EKS, RDS,
  Lambda, runtime and optional malware protection; IAM Access Analyzer for both
  external and unused access; optional Macie and Inspector.
- Three KMS customer-managed keys split by data domain with baseline-driven
  rotation periods and least-privilege key policies.
- Private-only baseline VPC with the default security group stripped, flow logs
  in Parquet to the archive, and gateway plus interface VPC endpoints carrying an
  organization perimeter policy.
- Evidence lake: EventBridge to Firehose to date-partitioned S3, catalogued in
  Glue with partition projection and queried through an Athena workgroup with
  saved auditor queries, a dead letter queue and a drop alarm.
- `scripts/export-evidence.sh` produces a read-only, manifest-stamped evidence
  bundle from a live account.
