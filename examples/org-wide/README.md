# Example: organization-wide, FedRAMP High

The complete posture. Everything on, nothing gated off, attached at the
organization root.

## What this deploys

| Layer | What lands |
|---|---|
| Preventive | 5 SCPs + 2 RCPs attached to the root, account-level S3 BPA, EBS encryption-by-default, IAM password policy at High parameters |
| Foundational | 3 KMS CMKs (multi-Region, 90-day rotation), organization CloudTrail with data events, log archive with 7-year Object Lock in COMPLIANCE mode, cross-region replication to `us-west-2` |
| Detective | Config org recorder + aggregator + 3 conformance packs, Security Hub (CIS v5.0, NIST 800-53 Rev 5, FSBP) with org auto-enable, GuardDuty with all protection plans incl. malware, Access Analyzer external + unused, Macie, Inspector |
| Monitoring | 15 CIS section-4 metric filters and alarms, plus a trail-delivery-failure alarm, all on one SNS topic |
| Network | Private-only VPC across 3 AZs, emptied default SG, flow logs to the archive at 60s aggregation, 8 interface + 2 gateway endpoints |
| Evidence | EventBridge → Firehose → partitioned S3 → Glue → Athena workgroup with saved auditor queries |

## What the `high` baseline changes versus `moderate`

Everything in this list comes from `local.baseline` in `terraform/locals.tf`:

- Object Lock retention 365 days → **2555 days**
- CloudWatch Logs retention 365 days → **1827 days**
- KMS rotation 365 days → **90 days**, keys become multi-Region
- Archive replication off → **on**, with a 15-minute replication SLA
- S3 PUTs: any SSE accepted → **`aws:kms` only** (the SCP condition changes)
- Session ceiling 12h → **1h**; password minimum 14 → **20** characters
- GuardDuty publishing 6h → **15 minutes**; Config delivery 24h → **3h**
- Access Analyzer unused-access age 90 days → **45 days**
- Availability zone floor 2 → **3**
- Flow log aggregation 600s → **60s**
- Conformance pack `fedramp-moderate.yaml` → `fedramp-high.yaml`

## Prerequisites

1. Run from the **Organizations management account** (or a delegated
   administrator holding the Organizations, CloudTrail, Config, Security Hub,
   GuardDuty, Macie and Inspector delegations).
2. `SERVICE_CONTROL_POLICY` and `RESOURCE_CONTROL_POLICY` policy types must be
   **enabled** in the organization first. Terraform will not enable them for you
   and the attachment fails with a bare `PolicyTypeNotEnabledException` if you
   forget.
3. Trusted access enabled for CloudTrail, Config, Security Hub, GuardDuty,
   Access Analyzer, Macie and Inspector.
4. Replace every `111111111111` / `222222222222` / `333333333333` /
   `o-exampleorgid` / `r-exam` placeholder.

## Running it

```bash
terraform init
terraform plan   # read every deny in the SCP diff before you apply
terraform apply
```

Attach to a **sandbox OU first**. A region allow-list applied at the root on a
Friday afternoon is a memorable experience. Move `target_ou_ids` to the root
only once you have watched a full business cycle without a legitimate
`AccessDenied`.

## Cost

Dominated by GuardDuty malware protection, CloudTrail data events, Config
configuration items and Macie. See the Cost section of the top-level README —
none of it is free and the numbers move by an order of magnitude with account
count and API volume.
