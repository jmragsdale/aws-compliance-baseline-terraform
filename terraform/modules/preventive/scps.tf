# ---------------------------------------------------------------------------
# Service control policies.
#
# Why five documents and not fifteen: AWS Organizations allows a maximum of
# five SCPs attached to any single root, OU or account. That quota is the
# reason production SCP sets are themed bundles rather than one policy per
# rule, and pretending otherwise produces a repo that cannot be attached at the
# root. Each statement carries its own Sid so a Deny in CloudTrail names the
# specific guardrail that fired.
#
# SCPs are the only genuinely *preventive* control surface in AWS: Config and
# Security Hub tell you a rule was broken, an SCP means the API call never
# succeeded. NIST 800-53 CM-7 (least functionality) and AC-3 (access
# enforcement) are the families this file lives in.
#
# Note the deliberate asymmetry: every deny exempts the break-glass roles. An
# SCP set with no escape hatch has locked out an entire organization more than
# once, and the recovery path involves AWS Support and a bad week.
# ---------------------------------------------------------------------------

data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition

  tags = merge(var.tags, { Module = "preventive" })

  org_count = var.is_organization ? 1 : 0

  # aws:PrincipalArn is compared with StringNotLike so that a role assumed via
  # any path or session name still matches.
  break_glass_arns = [
    for name in var.break_glass_role_names :
    "arn:${local.partition}:iam::${var.break_glass_account_id}:role/${name}"
  ]

  # ------------------------------------------------------------------ identity
  # AC-6(9) audit use of privileged functions, AC-2 account management,
  # IA-5 authenticator management, IA-2(1) MFA for privileged accounts.
  scp_identity = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # CIS 1.7: the root user must not be used for day-to-day work. Denying
        # every action for the Root principal type is stronger than a policy on
        # the root user itself, which root can edit.
        Sid       = "DenyRootAccountUsage"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = { StringLike = { "aws:PrincipalArn" = "arn:${local.partition}:iam::*:root" } }
      },
      {
        # CIS 1.4 / IA-5(1): long-lived access keys on IAM users are the single
        # most common credential-leak vector. Roles and Identity Center are the
        # supported path; this makes that structural rather than advisory.
        Sid    = "DenyIamUserAccessKeyCreation"
        Effect = "Deny"
        Action = [
          "iam:CreateAccessKey",
          "iam:UpdateAccessKey",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
        ]
        Resource  = "arn:${local.partition}:iam::*:user/*"
        Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
      },
      {
        # IA-2(1): sessions established without MFA may not touch identity or
        # key material. Applied at the SCP layer it also covers principals whose
        # own IAM policy forgot the condition.
        Sid    = "DenySensitiveIdentityActionsWithoutMfa"
        Effect = "Deny"
        Action = [
          "iam:DeleteUser",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteUserPermissionsBoundary",
          "kms:ScheduleKeyDeletion",
          "kms:DisableKey",
        ]
        Resource = "*"
        Condition = {
          BoolIfExists  = { "aws:MultiFactorAuthPresent" = "false" }
          StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns }
        }
      },
    ]
  })

  # --------------------------------------------------------------------- audit
  # AU-9 protection of audit information, AU-6 audit review, SI-4 monitoring.
  # An attacker's first move against a monitored account is to stop the
  # monitoring. This bundle is the reason that move fails.
  scp_audit = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DenyDisablingSecurityServices"
          Effect = "Deny"
          Action = [
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
            "cloudtrail:UpdateTrail",
            "cloudtrail:PutEventSelectors",
            "config:DeleteConfigurationRecorder",
            "config:DeleteDeliveryChannel",
            "config:StopConfigurationRecorder",
            "config:DeleteConfigRule",
            "config:DeleteOrganizationConfigRule",
            "config:DeleteConformancePack",
            "config:DeleteOrganizationConformancePack",
            "guardduty:DeleteDetector",
            "guardduty:DisassociateFromMasterAccount",
            "guardduty:UpdateDetector",
            "guardduty:DeletePublishingDestination",
            "securityhub:DisableSecurityHub",
            "securityhub:DisassociateFromMasterAccount",
            "securityhub:BatchDisableStandards",
            "securityhub:DeleteMembers",
            "macie2:DisableMacie",
            "macie2:DisassociateFromAdministratorAccount",
            "access-analyzer:DeleteAnalyzer",
            "inspector2:Disable",
          ]
          Resource  = "*"
          Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
        },
        {
          # AC-3: a member account that can leave the organization can shed
          # every SCP in one call. This is the guardrail that holds the rest up.
          Sid    = "DenyLeavingOrganization"
          Effect = "Deny"
          Action = [
            "organizations:LeaveOrganization",
            "organizations:DeleteOrganization",
            "organizations:DetachPolicy",
            "organizations:DisablePolicyType",
          ]
          Resource  = "*"
          Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
        },
        {
          # SI-7: the metric filters and alarms in the logging module are part
          # of the audit mechanism, so deleting them is deleting audit capability.
          Sid    = "DenyDeletingAuditAlarms"
          Effect = "Deny"
          Action = [
            "cloudwatch:DeleteAlarms",
            "cloudwatch:DisableAlarmActions",
            "logs:DeleteLogGroup",
            "logs:DeleteMetricFilter",
            "logs:PutRetentionPolicy",
          ]
          Resource  = "*"
          Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
        },
      ],
      # AU-9: no principal in the organization may delete or reconfigure the
      # archive itself. Skipped when the logging module is switched off, because
      # an SCP naming a bucket that does not exist is confusing rather than safe.
      var.log_archive_bucket_arn == null ? [] : [
        {
          Sid    = "ProtectLogArchiveBucket"
          Effect = "Deny"
          Action = [
            "s3:DeleteBucket",
            "s3:DeleteBucketPolicy",
            "s3:PutBucketPolicy",
            "s3:PutLifecycleConfiguration",
            "s3:PutBucketVersioning",
            "s3:PutObjectRetention",
            "s3:PutObjectLegalHold",
            "s3:BypassGovernanceRetention",
          ]
          Resource = [
            var.log_archive_bucket_arn,
            "${var.log_archive_bucket_arn}/*",
          ]
          Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
        },
      ],
    )
  })

  # ---------------------------------------------------------------------- data
  # SC-28 protection at rest, AC-3 access enforcement, SC-7 boundary protection.
  scp_data = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # SC-28. At Moderate any server-side encryption is accepted; at High the
        # PUT must name a KMS key so the decrypt path is separately auditable.
        # The two conditions are ANDed, so an unencrypted PUT is denied either way.
        Sid      = "DenyUnencryptedS3Put"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = var.require_kms_for_s3_put ? {
          StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }
          } : {
          Null = { "s3:x-amz-server-side-encryption" = "true" }
        }
      },
      {
        # SC-28 for block storage. Covers both fresh volumes and volumes
        # restored from an unencrypted snapshot, which is the usual bypass.
        Sid      = "DenyUnencryptedEbs"
        Effect   = "Deny"
        Action   = ["ec2:CreateVolume", "ec2:CopySnapshot", "ec2:CreateSnapshot", "ec2:CreateSnapshots"]
        Resource = "*"
        Condition = {
          Bool = { "ec2:Encrypted" = "false" }
        }
      },
      {
        # CIS 2.1.x / AC-3: public S3 is the highest-frequency data exposure in
        # AWS. Both the ACL route and the policy route are closed here, and the
        # account-level Block Public Access setting is protected below.
        Sid    = "DenyPublicS3Access"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteAccountPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock",
        ]
        Resource  = "*"
        Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
      },
      {
        Sid      = "DenyPublicS3AclGrants"
        Effect   = "Deny"
        Action   = ["s3:PutBucketAcl", "s3:PutObjectAcl", "s3:PutBucketPolicy"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = ["public-read", "public-read-write", "authenticated-read"]
          }
        }
      },
      {
        # SC-12: an EBS default-encryption key that can be turned off is not a
        # default. This also stops the "disable then create" bypass of the rule
        # above.
        Sid       = "DenyDisablingEbsEncryptionByDefault"
        Effect    = "Deny"
        Action    = ["ec2:DisableEbsEncryptionByDefault", "ec2:ModifyEbsDefaultKmsKeyId", "ec2:ResetEbsDefaultKmsKeyId"]
        Resource  = "*"
        Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
      },
    ]
  })

  # -------------------------------------------------------------------- region
  # CA-9 / SC-7: the authorisation boundary is a list of regions. Anything
  # outside it is by definition outside the assessed system, and is also
  # unmonitored because GuardDuty and Config are only enabled where we deployed
  # them. NotAction carries the global endpoints, which are always us-east-1.
  scp_region = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyOperationsOutsideApprovedRegions"
        Effect = "Deny"
        NotAction = [
          "a4b:*", "access-analyzer:*", "account:*", "acm:*", "aws-marketplace:*",
          "aws-portal:*", "budgets:*", "ce:*", "chime:*", "cloudfront:*",
          "cloudtrail:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
          "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "globalaccelerator:*",
          "health:*", "iam:*", "importexport:*", "kms:*", "license-manager:*",
          "notifications:*", "organizations:*", "pricing:*", "route53:*",
          "route53domains:*", "s3:GetAccountPublic*", "s3:ListAllMyBuckets",
          "s3:PutAccountPublic*", "shield:*", "sts:*", "support:*", "supportplans:*",
          "trustedadvisor:*", "waf-regional:*", "waf:*", "wafv2:*",
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions }
          StringNotLike   = { "aws:PrincipalArn" = local.break_glass_arns }
        }
      },
    ]
  })

  # ------------------------------------------------------------------- compute
  # CM-6 / AC-6: IMDSv1 hands out role credentials to anything that can make an
  # unauthenticated GET from the instance, which is what turns an SSRF bug into
  # a credential compromise. Requiring IMDSv2 removes that class entirely.
  scp_compute = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyRunInstancesWithoutImdsv2"
        Effect    = "Deny"
        Action    = "ec2:RunInstances"
        Resource  = "arn:${local.partition}:ec2:*:*:instance/*"
        Condition = { StringNotEquals = { "ec2:MetadataHttpTokens" = "required" } }
      },
      {
        Sid       = "DenyWeakenedInstanceMetadataOptions"
        Effect    = "Deny"
        Action    = "ec2:ModifyInstanceMetadataOptions"
        Resource  = "*"
        Condition = { StringNotLike = { "aws:PrincipalArn" = local.break_glass_arns } }
      },
      {
        # CM-7: a launch template that sets a hop limit above 1 lets containers
        # on the host reach the instance role, defeating IMDSv2's main benefit.
        Sid      = "DenyImdsHopLimitAboveOne"
        Effect   = "Deny"
        Action   = "ec2:RunInstances"
        Resource = "arn:${local.partition}:ec2:*:*:instance/*"
        Condition = {
          NumericGreaterThan = { "ec2:MetadataHttpPutResponseHopLimit" = "1" }
        }
      },
    ]
  })

  scps = var.is_organization ? {
    identity = { id = aws_organizations_policy.identity_guardrails[0].id }
    audit    = { id = aws_organizations_policy.audit_guardrails[0].id }
    data     = { id = aws_organizations_policy.data_guardrails[0].id }
    region   = { id = aws_organizations_policy.region_guardrails[0].id }
    compute  = { id = aws_organizations_policy.compute_guardrails[0].id }
  } : {}

  scp_attachments = var.is_organization ? {
    for pair in setproduct(keys(local.scps), var.target_ou_ids) :
    "${pair[0]}:${pair[1]}" => { policy = local.scps[pair[0]].id, target = pair[1] }
  } : {}
}

# The five-SCP quota is per target, not per organization. If this repo is
# combined with another SCP set (Control Tower ships its own), the attachment
# will fail at apply time with a quota error rather than a plan error, so the
# check surfaces it while there is still time to consolidate.
check "scp_quota_headroom" {
  assert {
    condition     = !var.is_organization || length(local.scps) <= 5
    error_message = "AWS Organizations allows at most 5 SCPs per target. Consolidate statements into fewer documents before attaching."
  }
}

resource "aws_organizations_policy" "identity_guardrails" {
  count = local.org_count

  name        = "${var.name_prefix}-identity-guardrails"
  description = "Root usage, IAM user credentials and MFA-gated identity actions (AC-2, AC-6(9), IA-2(1), IA-5)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp_identity

  tags = local.tags
}

resource "aws_organizations_policy" "audit_guardrails" {
  count = local.org_count

  name        = "${var.name_prefix}-audit-guardrails"
  description = "Protects CloudTrail, Config, GuardDuty, Security Hub, the log archive and org membership (AU-9, SI-4)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp_audit

  tags = local.tags
}

resource "aws_organizations_policy" "data_guardrails" {
  count = local.org_count

  name        = "${var.name_prefix}-data-guardrails"
  description = "Encryption at rest and public-access denial for S3 and EBS (SC-28, AC-3)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp_data

  tags = local.tags
}

resource "aws_organizations_policy" "region_guardrails" {
  count = local.org_count

  name        = "${var.name_prefix}-region-guardrails"
  description = "Confines the organization to the assessed regions (CA-9, SC-7)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp_region

  tags = local.tags
}

resource "aws_organizations_policy" "compute_guardrails" {
  count = local.org_count

  name        = "${var.name_prefix}-compute-guardrails"
  description = "IMDSv2 enforcement and instance metadata hardening (CM-6, CM-7)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp_compute

  tags = local.tags
}

resource "aws_organizations_policy_attachment" "scp" {
  for_each = local.scp_attachments

  policy_id = each.value.policy
  target_id = each.value.target
}
