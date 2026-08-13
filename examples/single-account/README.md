# Example: single account, FedRAMP Moderate

The shape you can actually run today without owning an AWS Organization.

## What this deploys

| Layer | What lands |
|---|---|
| Preventive | Account-level S3 Block Public Access, EBS encryption-by-default pointed at a CMK, IAM password policy at Moderate parameters. **No SCPs, no RCPs.** |
| Foundational | 3 KMS CMKs (single-Region, annual rotation), account CloudTrail (multi-region, log file validation, CWL integration), log archive with 1-year Object Lock in COMPLIANCE mode |
| Detective | Config recorder + delivery channel + 3 conformance packs (account-scoped), Security Hub with CIS v5.0 / NIST 800-53 Rev 5 / FSBP, GuardDuty with S3, EKS, RDS, Lambda and runtime protection, Access Analyzer (ACCOUNT + ACCOUNT_UNUSED_ACCESS) |
| Monitoring | All 15 CIS section-4 metric filters and alarms on one SNS topic |
| Network | Off |
| Evidence | Off |

## What `deployment_scope = "single_account"` gates off

Every resource below is created only in `organization` mode, because the API
call fails from anywhere other than an Organizations management or delegated
admin account:

- `aws_organizations_policy.*` — all 5 SCPs and both RCPs
- `aws_organizations_policy_attachment.scp` / `.rcp`
- `aws_cloudtrail.org` stays, but with `is_organization_trail = false`
- `aws_securityhub_organization_admin_account` / `_organization_configuration`
- `aws_guardduty_organization_admin_account` / `_organization_configuration`
- `aws_config_configuration_aggregator.org` and the org conformance packs
  (`aws_config_organization_conformance_pack.org` → `aws_config_conformance_pack.account`)
- `aws_macie2_organization_admin_account`, `aws_inspector2_delegated_admin_account`,
  `aws_inspector2_organization_configuration`
- Access Analyzer type flips `ORGANIZATION` → `ACCOUNT`

## The honest limitation

Without SCPs there is nothing *preventive* here beyond the three account
settings, and even those can be reverted by anyone with the right IAM
permissions in this account. The detective layer will tell you it happened. It
will not stop it.

That gap is the whole reason the organization shape exists, and it is the
reason a FedRAMP boundary is never a single account.

## Running it

```bash
terraform init
terraform plan
terraform apply
```

Then subscribe to the alarm topic — `security_alarms_topic_arn` — or the
fifteen CIS alarms fire into nothing. Setting `security_contact_email` on the
module creates the subscription for you, but AWS still requires the confirmation
click in the email.

## Cost

Roughly $30–80/month for an idle lab account: Config configuration items are the
largest line, then Security Hub checks, then GuardDuty. Three CMKs are $3/month.
S3 storage on an idle account is cents. Turning on `enable_cloudtrail_data_events`
is what changes the order of magnitude, which is why it is off here.

**Object Lock in COMPLIANCE mode cannot be shortened or removed.** With
`fedramp_baseline = "moderate"` the archive holds every object for 365 days and
you will pay for that storage whether or not you destroy the rest of the stack.
Use a short-lived account if you are only kicking the tyres.
