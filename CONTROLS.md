<!-- GENERATED FILE - do not edit by hand.
     Source: controls/controls.yaml   Regenerate: python3 controls/render.py -->

# Control Matrix - Amazon Web Services

77 implemented controls, each backed by a Terraform address that CI verifies exists.

## Framework coverage

| Framework | Version | Controls implemented | Distinct framework IDs mapped |
|---|---|---:|---:|
| FedRAMP Rev 5 | Rev 5 (Moderate / High) | 77 / 77 | 64 |
| NIST SP 800-53 Rev 5 | Rev 5 | 77 / 77 | 54 |
| CIS AWS Foundations Benchmark | v5.0 | 36 / 77 | 42 |

> **Read this honestly:** these numbers count *technical* controls implemented in Terraform. They are not an assessment, an ATO, or a claim of full baseline coverage. Administrative and procedural control families (AT, PS, PE, and much of PL/PM) cannot be implemented in infrastructure code at all.

## Enforcement split

| Type | Count | Meaning |
|---|---:|---|
| preventive | 33 | blocks the non-compliant configuration from being created |
| detective | 25 | detects and reports the non-compliant configuration |
| foundational | 19 | provides the substrate other controls depend on (logging, keys, scope) |

## Matrix

| ID | Control | Type | Module | FedRAMP | 800-53r5 | CIS v5.0 | Demo-safe | Billable |
|---|---|---|---|---|---|---|---|---|
| `DAT-001` | Unencrypted S3 PUT denied (aws:kms required at High) | preventive | `preventive` | SC-28, SC-28(1) | SC-28, SC-28(1) | 2.1.1 | no | no |
| `DAT-002` | Unencrypted EBS volume, snapshot and snapshot-copy creation denied | preventive | `preventive` | SC-28 | SC-28 | 2.2.1 | no | no |
| `DAT-003` | Public S3 ACL grants and public bucket policies denied | preventive | `preventive` | AC-3, AC-21, SC-7 | AC-3, AC-21 | 2.1.4 | no | no |
| `DAT-004` | Account-level S3 Block Public Access, all four settings | preventive | `preventive` | AC-3, AC-21 | AC-3 | 2.1.4 | yes | no |
| `DAT-005` | EBS encryption by default, pointed at a customer-managed key | preventive | `preventive` | SC-28, SC-12 | SC-28, SC-12 | 2.2.1 | yes | yes |
| `DAT-006` | Disabling EBS encryption-by-default denied | preventive | `preventive` | SC-12, SC-28, CM-7 | SC-12, CM-7 | - | no | no |
| `DAT-007` | Sensitive data discovery in S3 | detective | `detective` | RA-2, MP-4, SC-28 | RA-2, MP-4 | - | yes | yes |
| `DAT-008` | Block Public Access and ownership controls on every bucket this repo creates | preventive | `logging` | AC-3, AC-21 | AC-3 | 2.1.4 | yes | no |
| `DET-001` | Security Hub enabled with per-standard control findings | detective | `detective` | CA-7, RA-5, SI-4 | CA-7, RA-5 | 4.16 | yes | yes |
| `DET-002` | CIS AWS Foundations Benchmark v5.0 standard subscription | detective | `detective` | CA-7, CM-6 | CA-7, CM-6 | 1.1, 2.1.1, 3.1, 4.1, 5.1 | yes | yes |
| `DET-003` | NIST SP 800-53 Rev 5 standard subscription | detective | `detective` | CA-7, CA-2, RA-5 | CA-7, CA-2 | - | yes | yes |
| `DET-004` | AWS Foundational Security Best Practices standard subscription | detective | `detective` | CA-7, SI-2 | CA-7, SI-2 | - | yes | yes |
| `DET-005` | Security Hub delegated administration and organization auto-enable | detective | `detective` | AC-5, CA-7, CM-2 | AC-5, CA-7 | - | no | yes |
| `DET-006` | AWS Config recorder and delivery channel recording all supported types | detective | `detective` | CM-8, CM-3, CM-6, CA-7 | CM-8, CM-3, CM-6 | 3.5 | yes | yes |
| `DET-007` | Organization-wide Config aggregator | detective | `detective` | CM-8, CA-7, AU-6 | CM-8, CA-7 | - | no | yes |
| `DET-008` | Conformance packs: FedRAMP (baseline-selected), NIST 800-53 Rev 5, CIS v5.0 | detective | `detective` | CA-7, CM-6, RA-5 | CA-7, CM-6 | 3.5 | yes | yes |
| `DET-009` | GuardDuty detector with baseline-driven publishing frequency | detective | `detective` | SI-4, SI-4(2), RA-5, IR-4 | SI-4, SI-4(2), RA-5 | - | yes | yes |
| `DET-010` | GuardDuty S3, EKS audit, RDS login, Lambda network, runtime and malware protection | detective | `detective` | SI-3, SI-4, AU-2 | SI-3, SI-4 | - | yes | yes |
| `DET-011` | GuardDuty organization auto-enable for existing and future accounts | detective | `detective` | SI-4, CM-2, AC-5 | SI-4, CM-2 | - | no | yes |
| `DET-012` | Inspector v2 continuous vulnerability scanning for EC2, ECR and Lambda | detective | `detective` | RA-5, RA-5(2), SI-2, SI-2(2) | RA-5, SI-2 | - | yes | yes |
| `ENC-001` | Dedicated audit-log CMK with baseline-driven rotation | foundational | `encryption` | SC-12, SC-12(1), SC-28, AU-9 | SC-12, SC-12(1), SC-28 | 3.7 | yes | yes |
| `ENC-002` | Dedicated compliance-evidence CMK | foundational | `encryption` | SC-12, SC-28, AU-9 | SC-12, SC-28 | 3.7 | yes | yes |
| `ENC-003` | Dedicated general workload CMK for EBS, RDS, Secrets Manager and SSM | foundational | `encryption` | SC-12, SC-28 | SC-12, SC-28 | 3.7 | yes | yes |
| `ENC-004` | Least-privilege key policies with an organization perimeter | preventive | `encryption` | AC-6, SC-12, SC-7 | AC-6, SC-12 | - | yes | no |
| `ENC-005` | Multi-Region replica key so replicated audit records stay decryptable | foundational | `encryption` | CP-9, CP-10, SC-12 | CP-9, SC-12 | - | no | yes |
| `ENC-006` | Default encryption on the log archive and evidence buckets | preventive | `logging` | SC-28, SC-28(1) | SC-28 | 2.1.1, 3.4 | yes | no |
| `ENC-007` | TLS required for every bucket, topic and queue | preventive | `logging` | SC-8, SC-8(1), SC-13 | SC-8, SC-8(1) | 2.1.2 | yes | no |
| `ENC-008` | Alarm notifications encrypted at rest | preventive | `logging` | SC-28 | SC-28 | - | yes | no |
| `ENC-009` | Evidence pipeline encrypted in the buffer and in the queue | preventive | `evidence` | SC-28, SC-8 | SC-28 | - | yes | yes |
| `EVD-001` | Every Security Hub finding streamed out of the 90-day window | detective | `evidence` | CA-7, AU-7, AU-11 | CA-7, AU-7 | - | yes | yes |
| `EVD-002` | Firehose delivery to date-partitioned S3 | foundational | `evidence` | AU-7, AU-4 | AU-7 | - | yes | yes |
| `EVD-003` | Evidence lake bucket with Object Lock and organization perimeter | foundational | `evidence` | AU-9, AU-11, SC-7 | AU-9, AU-11 | - | yes | yes |
| `EVD-004` | Glue catalog with partition projection instead of a crawler | foundational | `evidence` | AU-7, AU-6, CA-7 | AU-7, AU-6 | - | yes | no |
| `EVD-005` | Athena workgroup with enforced encryption, a cost ceiling and saved auditor queries | detective | `evidence` | AU-7, AU-6, AC-3 | AU-7, AU-6 | - | yes | yes |
| `EVD-006` | Dead letter queue and alarm for undeliverable findings | detective | `evidence` | AU-5, AU-5(1), IR-4 | AU-5, AU-5(1) | - | yes | yes |
| `EVD-007` | Read-only evidence bundle export from a live account | detective | `root` | CA-7, AU-7, CA-2 | CA-7, AU-7 | - | yes | no |
| `IAM-001` | IAM user access key and login profile creation denied | preventive | `preventive` | IA-5(1), AC-2, IA-2 | IA-5(1), AC-2 | 1.4, 1.14 | no | no |
| `IAM-002` | MFA required for privileged identity and key operations | preventive | `preventive` | IA-2(1), IA-2(2), AC-6(9) | IA-2(1), IA-2(2) | 1.10 | no | no |
| `IAM-003` | IAM account password policy at baseline-selected strength | preventive | `preventive` | IA-5(1), IA-5 | IA-5(1) | 1.8, 1.9 | yes | no |
| `IAM-004` | External access analysis across the organization | detective | `detective` | AC-3, AC-21, CA-7 | AC-3, AC-21 | 1.20 | yes | yes |
| `IAM-005` | Unused access, roles and credentials analysis | detective | `detective` | AC-6(7), AC-2(3), AC-6 | AC-6(7), AC-2(3) | 1.12 | yes | yes |
| `IAM-006` | Service roles scoped to a single delivery path | foundational | `detective` | AC-6, CM-7 | AC-6, CM-7 | 1.16 | yes | no |
| `IAM-007` | CloudTrail-to-CloudWatch role limited to one log group | foundational | `logging` | AC-6, AU-9 | AC-6, AU-9 | - | yes | no |
| `IAM-008` | Replication role limited to the archive source and replica | foundational | `logging` | AC-6, CP-9 | AC-6 | - | no | no |
| `LOG-001` | Organization CloudTrail covering all regions and global services | foundational | `logging` | AU-2, AU-3, AU-12 | AU-2, AU-3, AU-12 | 3.1 | yes | yes |
| `LOG-002` | CloudTrail log file validation (digest files) | foundational | `logging` | AU-9(3), SI-7, AU-10 | AU-9(3), SI-7 | 3.2 | yes | no |
| `LOG-003` | S3 object-level and Lambda invoke data events | detective | `logging` | AU-2, AU-12 | AU-2, AU-12 | 3.8 | yes | yes |
| `LOG-004` | Central log archive with Object Lock in COMPLIANCE mode | foundational | `logging` | AU-9, AU-9(3), AU-11 | AU-9, AU-11 | 3.3 | yes | yes |
| `LOG-005` | Versioning on every audit and evidence bucket | foundational | `logging` | AU-9, CP-9, SI-7 | AU-9, CP-9 | - | yes | yes |
| `LOG-006` | Lifecycle tiering aligned to the retention window | foundational | `logging` | AU-11, AU-4 | AU-11, AU-4 | - | yes | no |
| `LOG-007` | S3 server access logging on the archive | detective | `logging` | AU-2, AU-9(4) | AU-2, AU-9(4) | 3.6 | yes | yes |
| `LOG-008` | Cross-region replication of audit records with a 15-minute SLA | foundational | `logging` | CP-9, CP-9(1), CP-10 | CP-9, CP-10 | - | no | yes |
| `LOG-009` | CloudWatch Logs retention for trail events | foundational | `logging` | AU-11, AU-6(1) | AU-11, AU-6(1) | - | yes | yes |
| `LOG-010` | Fifteen CIS metric filters and alarms on the trail log group | detective | `logging` | AU-6, AU-6(1), SI-4(4), AC-7 | AU-6, AU-6(1), SI-4(4) | 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 4.11, 4.12, 4.13, 4.14, 4.15 | yes | yes |
| `LOG-011` | Alarm on the audit trail itself failing | detective | `logging` | AU-5, AU-5(1), SI-4 | AU-5, AU-5(1) | - | yes | yes |
| `LOG-012` | Single SNS topic for every security alarm, with an optional subscription | detective | `logging` | IR-4, IR-5, AU-6, SI-4 | IR-4, IR-5, AU-6 | 4.16 | yes | no |
| `LOG-013` | Bucket policy denying archive tampering and non-organization access | preventive | `logging` | AU-9, SC-7, AC-3 | AU-9, SC-7 | - | yes | no |
| `NET-001` | Default security group stripped of all rules | preventive | `network` | SC-7, CM-7, AC-4 | SC-7, CM-7 | 5.4 | yes | no |
| `NET-002` | Default network ACL constrained to the VPC CIDR | preventive | `network` | SC-7, AC-4 | SC-7, AC-4 | - | yes | no |
| `NET-003` | Private-only VPC with no internet gateway and no public IP assignment | preventive | `network` | SC-7, SC-7(3), AC-4 | SC-7, SC-7(3) | - | yes | no |
| `NET-004` | VPC flow logs in Parquet, delivered to the audit archive | detective | `network` | AU-2, AU-3, AU-12, SC-7 | AU-2, AU-3, AU-12 | 3.9 | yes | yes |
| `NET-005` | S3 and DynamoDB gateway endpoints | preventive | `network` | SC-7, SC-7(4), AC-4 | SC-7, AC-4 | - | yes | no |
| `NET-006` | Interface endpoints for KMS, Logs, Monitoring, STS, SSM and Config | preventive | `network` | SC-7, SC-7(4) | SC-7 | - | yes | yes |
| `NET-007` | Endpoint policies restricting endpoints to organization-owned resources | preventive | `network` | AC-4, SC-7, AC-21 | AC-4, SC-7 | - | yes | no |
| `NET-008` | Endpoint security group scoped to HTTPS from the VPC CIDR only | preventive | `network` | SC-7, CM-7 | SC-7, CM-7 | 5.1 | yes | no |
| `ORG-001` | Root account usage denied organization-wide | preventive | `preventive` | AC-6(9), IA-2(1), AC-2 | AC-6(9), AC-2 | 1.7 | no | no |
| `ORG-002` | Disabling CloudTrail, Config, GuardDuty, Security Hub, Macie, Inspector or Access Analyzer denied | preventive | `preventive` | AU-9, SI-4, CM-7 | AU-9, SI-4, CM-7 | 3.1, 3.5 | no | no |
| `ORG-003` | Leaving or dismantling the organization denied | preventive | `preventive` | AC-3, CM-7 | AC-3, CM-7 | - | no | no |
| `ORG-004` | Central log archive protected from deletion and policy change by SCP | preventive | `preventive` | AU-9, AU-11 | AU-9, AU-11 | 3.3 | no | no |
| `ORG-005` | Deleting audit alarms, metric filters or log groups denied | preventive | `preventive` | AU-9, SI-7, AU-6 | AU-9, SI-7 | - | no | no |
| `ORG-006` | Operations confined to the assessed regions | preventive | `preventive` | CA-9, SC-7, AC-3 | CA-9, SC-7 | - | no | no |
| `ORG-007` | EC2 instances must require IMDSv2 | preventive | `preventive` | CM-6, CM-7, AC-6 | CM-6, CM-7 | 5.6 | no | no |
| `ORG-008` | IMDS hop limit above 1 denied | preventive | `preventive` | CM-7, AC-6 | CM-7 | - | no | no |
| `ORG-009` | Resource control policy: organization data perimeter | preventive | `preventive` | SC-7, AC-4, AC-21 | SC-7, AC-4, AC-21 | - | no | no |
| `ORG-010` | Resource control policy: confused-deputy and plaintext transport denial | preventive | `preventive` | SC-7, SC-8, AC-4 | SC-7, SC-8 | 2.1.2 | no | no |
| `ORG-011` | Guardrails attached to OU or root targets within the Organizations quota | foundational | `preventive` | CM-7, AC-3 | CM-7 | - | no | no |
| `ORG-012` | Deployment scope gating so organization-only controls plan cleanly in a single account | foundational | `root` | CM-2, SA-3 | CM-2 | - | yes | no |

## Implementation index

Terraform addresses backing each control. CI fails if any of these stop existing.

| ID | Terraform addresses |
|---|---|
| `DAT-001` | `preventive:aws_organizations_policy.data_guardrails` |
| `DAT-002` | `preventive:aws_organizations_policy.data_guardrails` |
| `DAT-003` | `preventive:aws_organizations_policy.data_guardrails` |
| `DAT-004` | `preventive:aws_s3_account_public_access_block.this` |
| `DAT-005` | `preventive:aws_ebs_encryption_by_default.this`, `preventive:aws_ebs_default_kms_key.this` |
| `DAT-006` | `preventive:aws_organizations_policy.data_guardrails` |
| `DAT-007` | `detective:aws_macie2_account.this`, `detective:aws_macie2_organization_admin_account.this` |
| `DAT-008` | `logging:aws_s3_bucket_public_access_block.log_archive`, `logging:aws_s3_bucket_public_access_block.access_logs`, `logging:aws_s3_bucket_ownership_controls.log_archive`, `evidence:aws_s3_bucket_public_access_block.evidence`, `evidence:aws_s3_bucket_ownership_controls.evidence` |
| `DET-001` | `detective:aws_securityhub_account.this` |
| `DET-002` | `detective:aws_securityhub_standards_subscription.cis` |
| `DET-003` | `detective:aws_securityhub_standards_subscription.nist` |
| `DET-004` | `detective:aws_securityhub_standards_subscription.fsbp` |
| `DET-005` | `detective:aws_securityhub_organization_admin_account.this`, `detective:aws_securityhub_organization_configuration.this`, `detective:aws_securityhub_finding_aggregator.this`, `detective:aws_securityhub_configuration_policy.baseline`, `detective:aws_securityhub_configuration_policy_association.targets` |
| `DET-006` | `detective:aws_config_configuration_recorder.this`, `detective:aws_config_delivery_channel.this`, `detective:aws_config_configuration_recorder_status.this` |
| `DET-007` | `detective:aws_config_configuration_aggregator.org`, `detective:aws_iam_role.config_aggregator` |
| `DET-008` | `detective:aws_config_organization_conformance_pack.org`, `detective:aws_config_conformance_pack.account` |
| `DET-009` | `detective:aws_guardduty_detector.this` |
| `DET-010` | `detective:aws_guardduty_detector_feature.this` |
| `DET-011` | `detective:aws_guardduty_organization_admin_account.this`, `detective:aws_guardduty_organization_configuration.this`, `detective:aws_guardduty_organization_configuration_feature.this` |
| `DET-012` | `detective:aws_inspector2_enabler.this`, `detective:aws_inspector2_delegated_admin_account.this`, `detective:aws_inspector2_organization_configuration.this` |
| `ENC-001` | `encryption:aws_kms_key.logs`, `encryption:aws_kms_alias.logs` |
| `ENC-002` | `encryption:aws_kms_key.evidence`, `encryption:aws_kms_alias.evidence` |
| `ENC-003` | `encryption:aws_kms_key.general`, `encryption:aws_kms_alias.general` |
| `ENC-004` | `encryption:data.aws_iam_policy_document.logs`, `encryption:data.aws_iam_policy_document.evidence`, `encryption:data.aws_iam_policy_document.general` |
| `ENC-005` | `encryption:aws_kms_replica_key.logs`, `encryption:aws_kms_alias.logs_replica` |
| `ENC-006` | `logging:aws_s3_bucket_server_side_encryption_configuration.log_archive`, `evidence:aws_s3_bucket_server_side_encryption_configuration.evidence` |
| `ENC-007` | `logging:data.aws_iam_policy_document.log_archive`, `logging:data.aws_iam_policy_document.access_logs`, `logging:data.aws_iam_policy_document.security_alarms`, `evidence:data.aws_iam_policy_document.evidence`, `evidence:data.aws_iam_policy_document.findings_dlq` |
| `ENC-008` | `logging:aws_sns_topic.security_alarms` |
| `ENC-009` | `evidence:aws_kinesis_firehose_delivery_stream.findings`, `evidence:aws_sqs_queue.findings_dlq` |
| `EVD-001` | `evidence:aws_cloudwatch_event_rule.securityhub_findings`, `evidence:aws_cloudwatch_event_target.firehose` |
| `EVD-002` | `evidence:aws_kinesis_firehose_delivery_stream.findings`, `evidence:aws_iam_role.firehose`, `evidence:aws_iam_role_policy.firehose` |
| `EVD-003` | `evidence:aws_s3_bucket.evidence`, `evidence:aws_s3_bucket_object_lock_configuration.evidence`, `evidence:aws_s3_bucket_policy.evidence`, `evidence:aws_s3_bucket_lifecycle_configuration.evidence` |
| `EVD-004` | `evidence:aws_glue_catalog_database.evidence`, `evidence:aws_glue_catalog_table.findings` |
| `EVD-005` | `evidence:aws_athena_workgroup.auditor`, `evidence:aws_athena_named_query.open_critical_findings`, `evidence:aws_athena_named_query.control_coverage_by_framework` |
| `EVD-006` | `evidence:aws_sqs_queue.findings_dlq`, `evidence:aws_sqs_queue_policy.findings_dlq`, `evidence:aws_cloudwatch_metric_alarm.findings_dlq_not_empty` |
| `EVD-007` | `root:module.evidence`, `root:module.detective` |
| `IAM-001` | `preventive:aws_organizations_policy.identity_guardrails` |
| `IAM-002` | `preventive:aws_organizations_policy.identity_guardrails` |
| `IAM-003` | `preventive:aws_iam_account_password_policy.this` |
| `IAM-004` | `detective:aws_accessanalyzer_analyzer.external` |
| `IAM-005` | `detective:aws_accessanalyzer_analyzer.unused` |
| `IAM-006` | `detective:aws_iam_role.config`, `detective:aws_iam_role_policy.config_delivery`, `detective:data.aws_iam_policy_document.config_delivery` |
| `IAM-007` | `logging:aws_iam_role.cloudtrail_cwl`, `logging:aws_iam_role_policy.cloudtrail_cwl`, `logging:data.aws_iam_policy_document.cloudtrail_cwl_assume` |
| `IAM-008` | `logging:aws_iam_role.replication`, `logging:aws_iam_role_policy.replication`, `logging:data.aws_iam_policy_document.replication` |
| `LOG-001` | `logging:aws_cloudtrail.org` |
| `LOG-002` | `logging:aws_cloudtrail.org` |
| `LOG-003` | `logging:aws_cloudtrail.org` |
| `LOG-004` | `logging:aws_s3_bucket.log_archive`, `logging:aws_s3_bucket_object_lock_configuration.log_archive` |
| `LOG-005` | `logging:aws_s3_bucket_versioning.log_archive`, `logging:aws_s3_bucket_versioning.access_logs`, `evidence:aws_s3_bucket_versioning.evidence` |
| `LOG-006` | `logging:aws_s3_bucket_lifecycle_configuration.log_archive`, `logging:aws_s3_bucket_lifecycle_configuration.access_logs` |
| `LOG-007` | `logging:aws_s3_bucket.access_logs`, `logging:aws_s3_bucket_logging.log_archive`, `logging:aws_s3_bucket_policy.access_logs` |
| `LOG-008` | `logging:aws_s3_bucket_replication_configuration.log_archive`, `logging:aws_s3_bucket.log_archive_replica`, `logging:aws_s3_bucket_object_lock_configuration.log_archive_replica`, `logging:aws_s3_bucket_lifecycle_configuration.log_archive_replica` |
| `LOG-009` | `logging:aws_cloudwatch_log_group.cloudtrail` |
| `LOG-010` | `logging:aws_cloudwatch_log_metric_filter.cis`, `logging:aws_cloudwatch_metric_alarm.cis` |
| `LOG-011` | `logging:aws_cloudwatch_metric_alarm.trail_delivery_failure` |
| `LOG-012` | `logging:aws_sns_topic.security_alarms`, `logging:aws_sns_topic_policy.security_alarms`, `logging:aws_sns_topic_subscription.security_contact` |
| `LOG-013` | `logging:aws_s3_bucket_policy.log_archive`, `logging:data.aws_iam_policy_document.log_archive` |
| `NET-001` | `network:aws_default_security_group.baseline` |
| `NET-002` | `network:aws_default_network_acl.baseline` |
| `NET-003` | `network:aws_vpc.baseline`, `network:aws_subnet.private`, `network:aws_route_table.private`, `network:aws_route_table_association.private` |
| `NET-004` | `network:aws_flow_log.vpc` |
| `NET-005` | `network:aws_vpc_endpoint.gateway` |
| `NET-006` | `network:aws_vpc_endpoint.interface` |
| `NET-007` | `network:data.aws_iam_policy_document.endpoint_perimeter` |
| `NET-008` | `network:aws_security_group.endpoints`, `network:aws_vpc_security_group_ingress_rule.endpoints_https`, `network:aws_vpc_security_group_egress_rule.endpoints_https` |
| `ORG-001` | `preventive:aws_organizations_policy.identity_guardrails`, `preventive:aws_organizations_policy_attachment.scp` |
| `ORG-002` | `preventive:aws_organizations_policy.audit_guardrails`, `preventive:aws_organizations_policy_attachment.scp` |
| `ORG-003` | `preventive:aws_organizations_policy.audit_guardrails` |
| `ORG-004` | `preventive:aws_organizations_policy.audit_guardrails`, `logging:data.aws_iam_policy_document.log_archive`, `logging:aws_s3_bucket_policy.log_archive` |
| `ORG-005` | `preventive:aws_organizations_policy.audit_guardrails` |
| `ORG-006` | `preventive:aws_organizations_policy.region_guardrails`, `preventive:aws_organizations_policy_attachment.scp` |
| `ORG-007` | `preventive:aws_organizations_policy.compute_guardrails` |
| `ORG-008` | `preventive:aws_organizations_policy.compute_guardrails` |
| `ORG-009` | `preventive:aws_organizations_policy.rcp_data_perimeter`, `preventive:aws_organizations_policy_attachment.rcp` |
| `ORG-010` | `preventive:aws_organizations_policy.rcp_confused_deputy`, `preventive:aws_organizations_policy_attachment.rcp` |
| `ORG-011` | `preventive:aws_organizations_policy_attachment.scp`, `preventive:aws_organizations_policy_attachment.rcp` |
| `ORG-012` | `root:module.preventive`, `root:module.detective` |

## Reverse index (framework control -> repo control)

### FedRAMP Rev 5

| Framework control | Implemented by |
|---|---|
| AC-2 | `IAM-001`, `ORG-001` |
| AC-2(3) | `IAM-005` |
| AC-3 | `DAT-003`, `DAT-004`, `DAT-008`, `EVD-005`, `IAM-004`, `LOG-013`, `ORG-003`, `ORG-006`, `ORG-011` |
| AC-4 | `NET-001`, `NET-002`, `NET-003`, `NET-005`, `NET-007`, `ORG-009`, `ORG-010` |
| AC-5 | `DET-005`, `DET-011` |
| AC-6 | `ENC-004`, `IAM-005`, `IAM-006`, `IAM-007`, `IAM-008`, `ORG-007`, `ORG-008` |
| AC-6(7) | `IAM-005` |
| AC-6(9) | `IAM-002`, `ORG-001` |
| AC-7 | `LOG-010` |
| AC-21 | `DAT-003`, `DAT-004`, `DAT-008`, `IAM-004`, `NET-007`, `ORG-009` |
| AU-2 | `DET-010`, `LOG-001`, `LOG-003`, `LOG-007`, `NET-004` |
| AU-3 | `LOG-001`, `NET-004` |
| AU-4 | `EVD-002`, `LOG-006` |
| AU-5 | `EVD-006`, `LOG-011` |
| AU-5(1) | `EVD-006`, `LOG-011` |
| AU-6 | `DET-007`, `EVD-004`, `EVD-005`, `LOG-010`, `LOG-012`, `ORG-005` |
| AU-6(1) | `LOG-009`, `LOG-010` |
| AU-7 | `EVD-001`, `EVD-002`, `EVD-004`, `EVD-005`, `EVD-007` |
| AU-9 | `ENC-001`, `ENC-002`, `EVD-003`, `IAM-007`, `LOG-004`, `LOG-005`, `LOG-013`, `ORG-002`, `ORG-004`, `ORG-005` |
| AU-9(3) | `LOG-002`, `LOG-004` |
| AU-9(4) | `LOG-007` |
| AU-10 | `LOG-002` |
| AU-11 | `EVD-001`, `EVD-003`, `LOG-004`, `LOG-006`, `LOG-009`, `ORG-004` |
| AU-12 | `LOG-001`, `LOG-003`, `NET-004` |
| CA-2 | `DET-003`, `EVD-007` |
| CA-7 | `DET-001`, `DET-002`, `DET-003`, `DET-004`, `DET-005`, `DET-006`, `DET-007`, `DET-008`, `EVD-001`, `EVD-004`, `EVD-007`, `IAM-004` |
| CA-9 | `ORG-006` |
| CM-2 | `DET-005`, `DET-011`, `ORG-012` |
| CM-3 | `DET-006` |
| CM-6 | `DET-002`, `DET-006`, `DET-008`, `ORG-007` |
| CM-7 | `DAT-006`, `IAM-006`, `NET-001`, `NET-008`, `ORG-002`, `ORG-003`, `ORG-007`, `ORG-008`, `ORG-011` |
| CM-8 | `DET-006`, `DET-007` |
| CP-9 | `ENC-005`, `IAM-008`, `LOG-005`, `LOG-008` |
| CP-9(1) | `LOG-008` |
| CP-10 | `ENC-005`, `LOG-008` |
| IA-2 | `IAM-001` |
| IA-2(1) | `IAM-002`, `ORG-001` |
| IA-2(2) | `IAM-002` |
| IA-5 | `IAM-003` |
| IA-5(1) | `IAM-001`, `IAM-003` |
| IR-4 | `DET-009`, `EVD-006`, `LOG-012` |
| IR-5 | `LOG-012` |
| MP-4 | `DAT-007` |
| RA-2 | `DAT-007` |
| RA-5 | `DET-001`, `DET-003`, `DET-008`, `DET-009`, `DET-012` |
| RA-5(2) | `DET-012` |
| SA-3 | `ORG-012` |
| SC-7 | `DAT-003`, `ENC-004`, `EVD-003`, `LOG-013`, `NET-001`, `NET-002`, `NET-003`, `NET-004`, `NET-005`, `NET-006`, `NET-007`, `NET-008`, `ORG-006`, `ORG-009`, `ORG-010` |
| SC-7(3) | `NET-003` |
| SC-7(4) | `NET-005`, `NET-006` |
| SC-8 | `ENC-007`, `ENC-009`, `ORG-010` |
| SC-8(1) | `ENC-007` |
| SC-12 | `DAT-005`, `DAT-006`, `ENC-001`, `ENC-002`, `ENC-003`, `ENC-004`, `ENC-005` |
| SC-12(1) | `ENC-001` |
| SC-13 | `ENC-007` |
| SC-28 | `DAT-001`, `DAT-002`, `DAT-005`, `DAT-006`, `DAT-007`, `ENC-001`, `ENC-002`, `ENC-003`, `ENC-006`, `ENC-008`, `ENC-009` |
| SC-28(1) | `DAT-001`, `ENC-006` |
| SI-2 | `DET-004`, `DET-012` |
| SI-2(2) | `DET-012` |
| SI-3 | `DET-010` |
| SI-4 | `DET-001`, `DET-009`, `DET-010`, `DET-011`, `LOG-011`, `LOG-012`, `ORG-002` |
| SI-4(2) | `DET-009` |
| SI-4(4) | `LOG-010` |
| SI-7 | `LOG-002`, `LOG-005`, `ORG-005` |

### NIST SP 800-53 Rev 5

| Framework control | Implemented by |
|---|---|
| AC-2 | `IAM-001`, `ORG-001` |
| AC-2(3) | `IAM-005` |
| AC-3 | `DAT-003`, `DAT-004`, `DAT-008`, `IAM-004`, `ORG-003` |
| AC-4 | `NET-002`, `NET-005`, `NET-007`, `ORG-009` |
| AC-5 | `DET-005` |
| AC-6 | `ENC-004`, `IAM-006`, `IAM-007`, `IAM-008` |
| AC-6(7) | `IAM-005` |
| AC-6(9) | `ORG-001` |
| AC-21 | `DAT-003`, `IAM-004`, `ORG-009` |
| AU-2 | `LOG-001`, `LOG-003`, `LOG-007`, `NET-004` |
| AU-3 | `LOG-001`, `NET-004` |
| AU-4 | `LOG-006` |
| AU-5 | `EVD-006`, `LOG-011` |
| AU-5(1) | `EVD-006`, `LOG-011` |
| AU-6 | `EVD-004`, `EVD-005`, `LOG-010`, `LOG-012` |
| AU-6(1) | `LOG-009`, `LOG-010` |
| AU-7 | `EVD-001`, `EVD-002`, `EVD-004`, `EVD-005`, `EVD-007` |
| AU-9 | `EVD-003`, `IAM-007`, `LOG-004`, `LOG-005`, `LOG-013`, `ORG-002`, `ORG-004`, `ORG-005` |
| AU-9(3) | `LOG-002` |
| AU-9(4) | `LOG-007` |
| AU-11 | `EVD-003`, `LOG-004`, `LOG-006`, `LOG-009`, `ORG-004` |
| AU-12 | `LOG-001`, `LOG-003`, `NET-004` |
| CA-2 | `DET-003` |
| CA-7 | `DET-001`, `DET-002`, `DET-003`, `DET-004`, `DET-005`, `DET-007`, `DET-008`, `EVD-001`, `EVD-007` |
| CA-9 | `ORG-006` |
| CM-2 | `DET-011`, `ORG-012` |
| CM-3 | `DET-006` |
| CM-6 | `DET-002`, `DET-006`, `DET-008`, `ORG-007` |
| CM-7 | `DAT-006`, `IAM-006`, `NET-001`, `NET-008`, `ORG-002`, `ORG-003`, `ORG-007`, `ORG-008`, `ORG-011` |
| CM-8 | `DET-006`, `DET-007` |
| CP-9 | `ENC-005`, `LOG-005`, `LOG-008` |
| CP-10 | `LOG-008` |
| IA-2(1) | `IAM-002` |
| IA-2(2) | `IAM-002` |
| IA-5(1) | `IAM-001`, `IAM-003` |
| IR-4 | `LOG-012` |
| IR-5 | `LOG-012` |
| MP-4 | `DAT-007` |
| RA-2 | `DAT-007` |
| RA-5 | `DET-001`, `DET-009`, `DET-012` |
| SC-7 | `LOG-013`, `NET-001`, `NET-002`, `NET-003`, `NET-005`, `NET-006`, `NET-007`, `NET-008`, `ORG-006`, `ORG-009`, `ORG-010` |
| SC-7(3) | `NET-003` |
| SC-8 | `ENC-007`, `ORG-010` |
| SC-8(1) | `ENC-007` |
| SC-12 | `DAT-005`, `DAT-006`, `ENC-001`, `ENC-002`, `ENC-003`, `ENC-004`, `ENC-005` |
| SC-12(1) | `ENC-001` |
| SC-28 | `DAT-001`, `DAT-002`, `DAT-005`, `ENC-001`, `ENC-002`, `ENC-003`, `ENC-006`, `ENC-008`, `ENC-009` |
| SC-28(1) | `DAT-001` |
| SI-2 | `DET-004`, `DET-012` |
| SI-3 | `DET-010` |
| SI-4 | `DET-009`, `DET-010`, `DET-011`, `ORG-002` |
| SI-4(2) | `DET-009` |
| SI-4(4) | `LOG-010` |
| SI-7 | `LOG-002`, `ORG-005` |

### CIS AWS Foundations Benchmark

| Framework control | Implemented by |
|---|---|
| 1.1 | `DET-002` |
| 1.4 | `IAM-001` |
| 1.7 | `ORG-001` |
| 1.8 | `IAM-003` |
| 1.9 | `IAM-003` |
| 1.10 | `IAM-002` |
| 1.12 | `IAM-005` |
| 1.14 | `IAM-001` |
| 1.16 | `IAM-006` |
| 1.20 | `IAM-004` |
| 2.1.1 | `DAT-001`, `DET-002`, `ENC-006` |
| 2.1.2 | `ENC-007`, `ORG-010` |
| 2.1.4 | `DAT-003`, `DAT-004`, `DAT-008` |
| 2.2.1 | `DAT-002`, `DAT-005` |
| 3.1 | `DET-002`, `LOG-001`, `ORG-002` |
| 3.2 | `LOG-002` |
| 3.3 | `LOG-004`, `ORG-004` |
| 3.4 | `ENC-006` |
| 3.5 | `DET-006`, `DET-008`, `ORG-002` |
| 3.6 | `LOG-007` |
| 3.7 | `ENC-001`, `ENC-002`, `ENC-003` |
| 3.8 | `LOG-003` |
| 3.9 | `NET-004` |
| 4.1 | `DET-002`, `LOG-010` |
| 4.2 | `LOG-010` |
| 4.3 | `LOG-010` |
| 4.4 | `LOG-010` |
| 4.5 | `LOG-010` |
| 4.6 | `LOG-010` |
| 4.7 | `LOG-010` |
| 4.8 | `LOG-010` |
| 4.9 | `LOG-010` |
| 4.10 | `LOG-010` |
| 4.11 | `LOG-010` |
| 4.12 | `LOG-010` |
| 4.13 | `LOG-010` |
| 4.14 | `LOG-010` |
| 4.15 | `LOG-010` |
| 4.16 | `DET-001`, `LOG-012` |
| 5.1 | `DET-002`, `NET-008` |
| 5.4 | `NET-001` |
| 5.6 | `ORG-007` |

## Caveats and limitations

- **`DAT-001`** - The condition changes with the baseline: Moderate rejects PUTs with no server-side encryption at all, High rejects anything that is not aws:kms. Switching to High without also enabling customer-managed keys will start denying legitimate writes - the root module has a `check` block for this.
- **`DAT-004`** - Overrides every bucket-level setting in the account, including buckets created by modules nobody reviewed. Paired with DAT-003, which denies turning it off.
- **`DAT-005`** - Account and region scoped, so it must be applied in every region the organization operates in - the region allow-list (ORG-006) is what keeps that list short. The CMK is only set when `enable_customer_managed_keys` is true; otherwise the AWS-managed aws/ebs key remains.
- **`DAT-006`** - Closes the 'disable the default, then create the volume' bypass of DAT-002.
- **`DAT-007`** - Answers "where does controlled unclassified information actually live", which the data flow diagram in an SSP asserts and rarely proves. Metered per GB inspected; off by default for that reason.
- **`DAT-008`** - BucketOwnerEnforced disables ACLs entirely, which turns "no public ACL" from a thing to keep checking into a structural property.
- **`DET-001`** - control_finding_generator is STANDARD_CONTROL so a resource failing three standards produces three pieces of evidence rather than one ambiguous one. Security Hub makes nothing compliant; it continuously reports which published checks you currently fail.
- **`DET-002`** - The standards ARN is version-pinned. AWS publishes new benchmark versions without deprecating the old, and an unpinned subscription silently changes which checks you are measured against between applies.
- **`DET-003`** - Roughly 240 automated checks tagged with 800-53 control identifiers, which is what makes a Security Hub export usable as evidence against a control set rather than as a security score.
- **`DET-004`** - Not a compliance framework. Included because it covers service-specific misconfigurations that neither CIS nor the NIST standard reaches.
- **`DET-005`** - AC-5 separation of duties is why detective tooling is delegated to the security account rather than run from the management account, which holds the power to change the organization it would be watching. Uses *central* configuration: enablement is expressed as a configuration policy associated with an OU, not as a global auto-enable toggle, so a member account that drifts is corrected rather than merely reported. The legacy auto_enable flags must be off under central configuration - setting them alongside configuration_type = "CENTRAL" is rejected by the API at apply time.
- **`DET-006`** - Config is the only service producing a timestamped, queryable record of what existed and how it was configured at a past moment - which is what an assessor means by evidence. Recording a subset of resource types is the usual cost optimisation and the usual reason a CM-8 inventory claim falls apart under questioning.
- **`DET-007`** - Makes 'every unencrypted volume in the boundary' a single query rather than N console tabs.
- **`DET-008`** - IMPORTANT - these are trimmed, hand-maintained subsets of the AWS-published packs (25 / 35 / 24 rules respectively), not the full templates. The full FedRAMP pack is ~150 rules of CloudFormation that nobody reviews, and unreviewed rules produce unreviewed findings. Every rule included was chosen because a control in this matrix depends on it. If you need complete published-pack coverage, replace the files in terraform/modules/detective/templates/ with the AWS originals.
- **`DET-009`** - Covers what Config cannot see: Config knows what a resource looks like, GuardDuty knows what it is doing. Fifteen-minute publishing at High.
- **`DET-010`** - EBS malware protection is behind its own switch because it is by far the most expensive plan - it snapshots and scans volumes on a suspicious finding, charged per GB scanned.
- **`DET-011`** - auto_enable_organization_members is ALL, not NEW; NEW leaves existing accounts unmonitored.
- **`DET-012`** - Lambda code scanning is separately metered because it decompiles and analyses the package rather than reading the dependency manifest.
- **`ENC-001`** - Rotation every 365 days at Moderate, every 90 at High.
- **`ENC-004`** - Service principal grants carry aws:SourceArn or aws:SourceAccount conditions so another account's CloudTrail cannot use our key. The general key additionally denies all use by principals outside the organization.
- **`ENC-005`** - Only created at the High baseline. A cross-region replica of KMS-encrypted objects without a replica key is a copy nobody can read, which is a surprisingly common way to fail a recovery test.
- **`ENC-006`** - Falls back to SSE-S3 when `enable_customer_managed_keys` is false. The CIS 3.4 check for a CMK-encrypted trail only passes with CMKs on. Bucket keys are enabled to keep KMS request charges sane on log workloads.
- **`ENC-007`** - The archive additionally denies TLS below 1.2 via s3:TlsVersion, which is the FedRAMP floor and is not covered by aws:SecureTransport alone.
- **`ENC-008`** - Alarm bodies quote the offending principal and API call, which is exactly the reconnaissance an attacker would like. Falls back to the AWS-managed alias/aws/sns key when no CMK exists.
- **`ENC-009`** - Findings sit in the Firehose buffer for up to five minutes before landing.
- **`EVD-001`** - Security Hub retains findings for 90 days. Continuous monitoring under an ATO means monthly evidence for the life of the authorisation, so the window has to be escaped. Suppressed findings are included deliberately - an assessor asking "how do you know this was suppressed on purpose" needs them in the record.
- **`EVD-002`** - No Lambda transform: a transform function is one more thing to patch, and Firehose's own prefix templating already produces the Hive partitions the catalog needs.
- **`EVD-003`** - Findings describe exactly where an organization is weakest, so AU-9 and AC-6 apply at least as hard here as to the raw logs. Not cross-region replicated even at High - it is a derived artefact rebuildable from the archive, which is a conscious cost trade-off.
- **`EVD-004`** - The ASFF schema here is a deliberately shallow projection: the full schema is ~200 nested fields and changes as AWS adds services. The columns modelled are the ones an assessment question actually touches, and the raw detail struct is retained so nothing is lost. Partition projection avoids a scheduled crawler that costs money, lags reality and fails silently.
- **`EVD-005`** - enforce_workgroup_configuration means an auditor cannot write results into an unencrypted location, and bytes_scanned_cutoff_per_query stops a single SELECT * against a year of data becoming a four-figure line item.
- **`EVD-006`** - The audit trail of the audit trail. A non-empty DLQ means evidence was lost, which is a same-day problem rather than a backlog item.
- **`EVD-007`** - scripts/export-evidence.sh collects Security Hub control results, Config compliance, GuardDuty findings, CloudTrail delivery status, Access Analyzer findings, the IAM credential report and the Organizations policy set into a manifest-stamped bundle. Every call is read-only. It collects technical evidence only - the administrative families are gathered elsewhere and an assessor will ask for them separately.
- **`IAM-001`** - Pushes all human and workload access onto roles and Identity Center. Does not remove access keys that already exist; use the credential report from scripts/export-evidence.sh to find those.
- **`IAM-002`** - Covers deleting principals, removing permissions boundaries and disabling or scheduling deletion of KMS keys. It does not enforce MFA on every console login - that lives in Identity Center or in the IdP, neither of which this repo configures.
- **`IAM-003`** - 14 characters and 90-day maximum age at Moderate, 20 characters and 60 days at High. Applies only to IAM users with console passwords, which the identity guardrail (IAM-001) is trying to eliminate entirely - this is the belt to that suspenders.
- **`IAM-004`** - Uses automated reasoning rather than heuristics, so a "no external access" result is a proof over the resource policies rather than a scan that found nothing. Falls back to ACCOUNT scope in single-account mode.
- **`IAM-005`** - Metered per IAM role and user analysed per month, which makes it the one Access Analyzer feature with a real bill attached. Threshold is 90 days at Moderate, 45 at High.
- **`IAM-006`** - The Config recorder uses the AWS-managed read-only policy plus an inline policy limited to one bucket prefix, rather than a second managed policy with a broad write surface.
- **`IAM-008`** - Only created when the FedRAMP High baseline turns replication on.
- **`LOG-001`** - Organization trails cannot be stopped or reconfigured by member accounts, which is what makes AU-9 real rather than aspirational. In single-account mode this becomes an ordinary account trail and a sufficiently privileged local principal can turn it off.
- **`LOG-002`** - Hourly SHA-256 digest files. This is the difference between "we have logs" and "we can prove these are the logs", which is the question an assessor actually asks.
- **`LOG-003`** - Off by default and genuinely expensive on busy accounts. The selector excludes the archive bucket's own delivery writes, which would otherwise generate a self-referential feedback loop.
- **`LOG-004`** - COMPLIANCE mode cannot be shortened or bypassed by anyone including the account root and AWS Support. That is the point, and it is also why the bucket policy blocks `terraform destroy` of this bucket. Break-glass is an AWS Support case, not a Terraform flag. 365-day window at Moderate, 2555-day at High.
- **`LOG-005`** - Prerequisite for both Object Lock and replication; neither works without it.
- **`LOG-006`** - Expiration is deliberately set one day beyond the Object Lock window; set it earlier and S3 refuses every delete, generating noise and no savings.
- **`LOG-007`** - Without this, a principal who can read the audit archive leaves no trace of having done so. The access-log bucket has no Object Lock, because S3 will not deliver access logs into a bucket with a default retention period.
- **`LOG-008`** - High baseline only. Delete-marker replication is deliberately disabled so a deletion in the primary cannot hide the object in the replica. The replica carries its own Object Lock, because replication copies objects and not bucket-level protections.
- **`LOG-009`** - 365 days at Moderate, 1827 at High. Encrypted with the logs CMK when enabled.
- **`LOG-010`** - All fifteen of CIS section 4, generated from one table so none can quietly go missing. Each carries a default_value of 0 so a quiet period produces a real datapoint instead of INSUFFICIENT_DATA, which on a dashboard looks identical to "working fine".
- **`LOG-011`** - Watches for the *absence* of log delivery, because a trail that stops is silent by construction. treat_missing_data is set to breaching for the same reason.
- **`LOG-012`** - Email subscriptions still need the confirmation click; Terraform cannot complete that and the subscription sits in PendingConfirmation until someone does. An unconfirmed subscription means the alarms fire into nothing.
- **`LOG-013`** - Denies DeleteBucket, DeleteBucketPolicy, PutBucketVersioning, PutEncryptionConfiguration and PutBucketObjectLockConfiguration for every principal, with no exemption. This is intentionally stronger than the SCP and intentionally blocks `terraform destroy`.
- **`NET-001`** - AWS creates a default SG allowing all traffic between its members and it cannot be deleted, so the only remedy is to adopt it in state and empty it. An unmanaged default SG is the most common reason a "locked down" VPC turns out to be flat internally.
- **`NET-002`** - NACLs are stateless, so denying return traffic here breaks everything in a way that is hard to diagnose. Deliberately left permissive within the CIDR rather than made maximally strict.
- **`NET-003`** - Not "an internet gateway with a restrictive route table" - no gateway at all. Egress that does not exist cannot be misconfigured. AZ count floors at 2 (Moderate) or 3 (High).
- **`NET-004`** - Traffic type ALL rather than REJECT: rejects alone are cheaper and make lateral movement inside the VPC invisible. The custom log_format adds the fields that make a flow attributable (account, VPC, subnet, instance, pkt-srcaddr, traffic-path) which the default format omits. 60-second aggregation at High, 600 at Moderate.
- **`NET-005`** - Gateway endpoints are free. Traffic that leaves the VPC to reach S3 is both billable and un-inspectable.
- **`NET-006`** - Roughly $7/month per endpoint per AZ, which is why the list is the minimum the controls in this repo themselves depend on plus what Session Manager needs - Session Manager being how you administer instances without inbound SSH.
- **`NET-007`** - Without an endpoint policy, an endpoint is an unrestricted route to every account in AWS for that service - the "endpoint as exfiltration path" problem. aws:ResourceOrgID closes it.
- **`NET-008`** - Egress is scoped back to the VPC CIDR rather than left open, which is the usual default.
- **`ORG-001`** - Denies every action for the Root principal type. The root user can still perform the handful of operations AWS exempts from SCPs entirely (closing the account, changing the root password, changing the support plan), which is why CIS also requires hardware MFA on root - a control no Terraform resource can create.
- **`ORG-002`** - Exempts the break-glass roles named in `var.break_glass_role_names`. That exemption is deliberate and is itself a monitored path - see LOG-010, which alarms on CloudTrail and Config configuration changes regardless of who made them.
- **`ORG-003`** - This is the guardrail every other SCP depends on. A member account that can call LeaveOrganization sheds all of them in one API call.
- **`ORG-004`** - Two independent layers (SCP and bucket policy) plus Object Lock. The statement is omitted entirely when `enable_central_logging` is false, because an SCP naming a non-existent bucket is confusing rather than safe.
- **`ORG-006`** - The `NotAction` list carries the global endpoints (IAM, STS, CloudFront, Route 53, Organizations and friends) which are always evaluated in us-east-1. Omitting any of them breaks the organization in ways that are slow to diagnose. Verify the list against current AWS documentation before attaching at the root.
- **`ORG-007`** - Closes the SSRF-to-credential-theft path. Also denies ModifyInstanceMetadataOptions so the setting cannot be weakened after launch.
- **`ORG-008`** - A hop limit above 1 lets containers on the host reach instance metadata, which defeats most of IMDSv2's benefit. Note this will break some container runtimes that legitimately need a hop limit of 2 - test before attaching at the root.
- **`ORG-009`** - RCPs apply only to S3, STS, KMS, SQS and Secrets Manager. Resources of any other type are not covered, and describing this as a total perimeter would be wrong.
- **`ORG-011`** - AWS allows at most five policies of each type per target. The statements are therefore bundled into five themed SCPs rather than one policy per rule; a `check` block fails the plan if that ceiling is ever exceeded, and policies/guardrails.rego asserts the same thing against the plan JSON.
- **`ORG-012`** - `var.deployment_scope = "single_account"` count-gates every Organizations API call. The result is a genuinely smaller posture, not the same posture run cheaply - see examples/single-account/README.md for exactly what is lost.

## Framework notes

- FedRAMP Rev 5 control identifiers *are* NIST SP 800-53 Rev 5 identifiers - FedRAMP is a baseline selection plus parameter values, not a separate catalogue. The two columns therefore overlap heavily by construction. They are kept separate because the FedRAMP column reflects controls whose *parameters* this repo actually sets from `var.fedramp_baseline`, while the 800-53 column reflects the base control the implementation addresses.
- CIS AWS Foundations Benchmark v5.0 section numbers are used verbatim. Where a control is implemented preventively here but the benchmark checks it detectively (or vice versa), the mapping still applies - the benchmark does not care how you got there.
- No control in this file claims coverage of an administrative or procedural family. AT (awareness and training), PS (personnel security), PE (physical protection) and most of PL/PM have no Terraform representation and are absent on purpose rather than by oversight.
- Controls marked `demo_safe: false` require an AWS Organizations management account or a delegated administrator. They plan cleanly in `examples/single-account` because they are count-gated off, which means that example is a *smaller* posture, not the same posture more cheaply.
