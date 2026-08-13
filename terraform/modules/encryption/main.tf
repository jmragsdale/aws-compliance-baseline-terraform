# ---------------------------------------------------------------------------
# Customer-managed keys, one per data domain.
#
# Why separate keys instead of one account key: SC-12 and AC-6 both push toward
# a key whose policy can be reasoned about in isolation. A single shared key
# means every grant to any consumer is a grant to the audit trail as well. Three
# domains -- audit logs, compliance evidence, general workload data -- is the
# smallest split where the key policies genuinely differ.
#
# Why rotation is not optional: SC-12(1) expects a defined cryptoperiod. The
# period itself comes from the FedRAMP baseline (annual at Moderate, quarterly
# at High) rather than being hard-coded here.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  root_arn   = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"

  tags = merge(var.tags, { Module = "encryption" })
}

# --------------------------------------------------------------------- logs key

# AU-9: audit records must be protected from unauthorised modification and
# deletion. Encrypting them under a key whose policy only permits the logging
# services to encrypt -- and nobody to decrypt except the log archive and
# security tooling accounts -- is the technical half of that control.
data "aws_iam_policy_document" "logs" {
  # A KMS key policy is only ever evaluated for its own key, so Resource "*"
  # is the documented AWS idiom for "this key" rather than a wildcard grant --
  # there is no ARN to name that would not be circular. Scope comes from the
  # principal and condition blocks, which are narrow on every statement.
  # checkov:skip=CKV_AWS_109:Resource "*" in a KMS key policy addresses only the key the policy is attached to. Scope is enforced by the principal and aws:SourceArn / aws:SourceAccount / aws:PrincipalOrgID conditions.
  # checkov:skip=CKV_AWS_111:Same -- key policy resource scope is the key itself; write actions are constrained by service principal and source conditions.
  # checkov:skip=CKV_AWS_356:Same -- a key policy cannot name its own key ARN without circularity.
  # Without this statement the key is unmanageable: KMS requires the owning
  # account to retain administrative access or the key becomes orphaned.
  statement {
    sid       = "AccountKeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  # CloudTrail encrypts log files with this key. The SourceArn condition is what
  # stops another account's trail from using our key (the confused deputy shape
  # AWS documents for every service principal grant).
  statement {
    sid     = "CloudTrailEncrypt"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    # Scoping a key policy to a specific key ARN is circular; "*" here means
    # "this key" because a key policy is only ever evaluated for its own key.
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  # VPC flow log delivery and CloudWatch Logs both encrypt through the same
  # principal family. AU-2 requires the network audit records to exist; this is
  # what lets them be written encrypted.
  statement {
    sid       = "LogDeliveryEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:DescribeKey", "kms:ReEncrypt*"]
    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "delivery.logs.amazonaws.com",
        "logs.${local.region}.amazonaws.com",
        "config.amazonaws.com",
        "s3.amazonaws.com",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id, var.log_archive_account_id]
    }
  }

  # AU-9(4): read access to audit records is separated from the accounts that
  # produce them. Only the log archive owner and the delegated security admin
  # may decrypt, and only from inside the organization.
  statement {
    sid       = "AuditReadersDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:${local.partition}:iam::${var.log_archive_account_id}:root",
        "arn:${local.partition}:iam::${var.security_tooling_account_id}:root",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "${var.name_prefix} audit log encryption (AU-9, SC-12, SC-28)"
  deletion_window_in_days = var.deletion_window_days
  enable_key_rotation     = true
  rotation_period_in_days = var.rotation_days
  multi_region            = var.multi_region
  policy                  = data.aws_iam_policy_document.logs.json

  tags = merge(local.tags, { DataDomain = "audit-logs" })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# CP-9/CP-10: at the High baseline the audit archive is replicated to a second
# region, which is only useful if the objects can still be decrypted there. A
# multi-Region replica key shares key material with the primary so replicated
# objects need no re-encryption.
resource "aws_kms_replica_key" "logs" {
  count = var.create_replica && var.multi_region ? 1 : 0

  provider = aws.replica

  description             = "${var.name_prefix} audit log encryption replica (CP-9)"
  primary_key_arn         = aws_kms_key.logs.arn
  deletion_window_in_days = var.deletion_window_days
  policy                  = data.aws_iam_policy_document.logs.json

  tags = merge(local.tags, { DataDomain = "audit-logs" })
}

resource "aws_kms_alias" "logs_replica" {
  count = var.create_replica && var.multi_region ? 1 : 0

  provider = aws.replica

  name          = "alias/${var.name_prefix}-logs"
  target_key_id = aws_kms_replica_key.logs[0].key_id
}

# ----------------------------------------------------------------- evidence key

# The evidence lake holds Security Hub findings, which describe exactly where an
# organization is weakest. AU-9 and AC-6 apply to it at least as hard as to the
# raw logs, so it gets its own key rather than sharing the logs key.
data "aws_iam_policy_document" "evidence" {
  # A KMS key policy is only ever evaluated for its own key, so Resource "*"
  # is the documented AWS idiom for "this key" rather than a wildcard grant --
  # there is no ARN to name that would not be circular. Scope comes from the
  # principal and condition blocks, which are narrow on every statement.
  # checkov:skip=CKV_AWS_109:Resource "*" in a KMS key policy addresses only the key the policy is attached to. Scope is enforced by the principal and aws:SourceArn / aws:SourceAccount / aws:PrincipalOrgID conditions.
  # checkov:skip=CKV_AWS_111:Same -- key policy resource scope is the key itself; write actions are constrained by service principal and source conditions.
  # checkov:skip=CKV_AWS_356:Same -- a key policy cannot name its own key ARN without circularity.
  statement {
    sid       = "AccountKeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid       = "EvidencePipelineEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:DescribeKey", "kms:ReEncrypt*"]
    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "firehose.amazonaws.com",
        "delivery.logs.amazonaws.com",
        "s3.amazonaws.com",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # Auditors query through Athena from the security tooling account only.
  statement {
    sid       = "AuditorDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${var.security_tooling_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
  }
}

resource "aws_kms_key" "evidence" {
  description             = "${var.name_prefix} compliance evidence encryption (AU-9, SC-28)"
  deletion_window_in_days = var.deletion_window_days
  enable_key_rotation     = true
  rotation_period_in_days = var.rotation_days
  multi_region            = var.multi_region
  policy                  = data.aws_iam_policy_document.evidence.json

  tags = merge(local.tags, { DataDomain = "evidence" })
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${var.name_prefix}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

# ------------------------------------------------------------------ general key

# SC-28 for workload data: EBS encryption-by-default points at this key, so
# every volume created anywhere in the account inherits a CMK rather than the
# aws/ebs AWS-managed key, which cannot be revoked or audited per-grant.
data "aws_iam_policy_document" "general" {
  # A KMS key policy is only ever evaluated for its own key, so Resource "*"
  # is the documented AWS idiom for "this key" rather than a wildcard grant --
  # there is no ARN to name that would not be circular. Scope comes from the
  # principal and condition blocks, which are narrow on every statement.
  # checkov:skip=CKV_AWS_109:Resource "*" in a KMS key policy addresses only the key the policy is attached to. Scope is enforced by the principal and aws:SourceArn / aws:SourceAccount / aws:PrincipalOrgID conditions.
  # checkov:skip=CKV_AWS_111:Same -- key policy resource scope is the key itself; write actions are constrained by service principal and source conditions.
  # checkov:skip=CKV_AWS_356:Same -- a key policy cannot name its own key ARN without circularity.
  statement {
    sid       = "AccountKeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  # EC2/EBS and autoscaling reach the key through grants rather than direct
  # calls, which is why CreateGrant is scoped by the ViaService condition.
  statement {
    sid    = "AllowServiceUseViaAwsServices"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "ec2.${local.region}.amazonaws.com",
        "rds.${local.region}.amazonaws.com",
        "secretsmanager.${local.region}.amazonaws.com",
        "ssm.${local.region}.amazonaws.com",
      ]
    }
  }

  # Data perimeter: even inside the account, key use is denied to principals
  # outside the organization. This is the key-side half of the RCP perimeter.
  statement {
    sid       = "DenyOutsideOrganization"
    effect    = "Deny"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }

    condition {
      test     = "BoolIfExists"
      variable = "aws:PrincipalIsAWSService"
      values   = ["false"]
    }
  }
}

resource "aws_kms_key" "general" {
  description             = "${var.name_prefix} general workload data encryption (SC-28)"
  deletion_window_in_days = var.deletion_window_days
  enable_key_rotation     = true
  rotation_period_in_days = var.rotation_days
  multi_region            = false
  policy                  = data.aws_iam_policy_document.general.json

  tags = merge(local.tags, { DataDomain = "general" })
}

resource "aws_kms_alias" "general" {
  name          = "alias/${var.name_prefix}-general"
  target_key_id = aws_kms_key.general.key_id
}
