# ---------------------------------------------------------------------------
# AWS Config.
#
# CM-8 (system component inventory) is the control most people miss when they
# think of Config as "the thing Security Hub needs". Config is the only service
# that produces a timestamped, queryable record of what existed and how it was
# configured at any past moment. That record is what an assessor means by
# "evidence", and it is what makes CM-3 (configuration change control) and
# CM-6 (configuration settings) auditable after the fact rather than assertions.
#
# Security Hub's standards run *on top of* Config's configuration items. No
# recorder, no CIS score.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  count = local.config_count

  name               = "${var.name_prefix}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json

  tags = local.tags
}

# AWS_ConfigRole is the AWS-managed policy for the recorder. It is read-only
# across every service, which is the point: the recorder must be able to
# describe everything and change nothing.
resource "aws_iam_role_policy_attachment" "config_managed" {
  count = local.config_count

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

# AC-6: delivery permissions are granted explicitly rather than through a second
# managed policy, so the write surface of this role is one bucket prefix.
data "aws_iam_policy_document" "config_delivery" {
  count = local.config_count

  statement {
    sid       = "DeliverConfigSnapshots"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:PutObjectAcl"]
    resources = ["arn:${local.partition}:s3:::${var.log_archive_bucket_name}/config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "ReadArchiveBucketAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:${local.partition}:s3:::${var.log_archive_bucket_name}"]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []

    content {
      sid       = "EncryptDeliveredSnapshots"
      effect    = "Allow"
      actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:DescribeKey"]
      resources = [var.kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  count = local.config_count

  name   = "${var.name_prefix}-config-delivery"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_delivery[0].json
}

resource "aws_config_configuration_recorder" "this" {
  count = local.config_count

  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    # CM-8 demands a complete inventory. Recording a subset of resource types is
    # the standard cost optimisation and the standard reason an inventory claim
    # falls apart under questioning.
    all_supported = true

    # IAM, S3 and other global resources are only recorded in one region;
    # recording them everywhere multiplies configuration items for no gain.
    include_global_resource_types = true
  }

  recording_mode {
    # CONTINUOUS is required for change-triggered rules to evaluate at all.
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "this" {
  count = local.config_count

  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.log_archive_bucket_name
  s3_key_prefix  = "config"
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = var.config_delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = local.config_count

  # checkov:skip=CKV2_AWS_45:The linked recorder sets recording_group.all_supported = true and include_global_resource_types = true (see aws_config_configuration_recorder.this above). The graph check cannot resolve the reference across the count index.

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# ------------------------------------------------------------------ aggregator

data "aws_iam_policy_document" "config_aggregator_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config_aggregator" {
  count = var.enable_config && var.is_organization ? 1 : 0

  name               = "${var.name_prefix}-config-aggregator"
  assume_role_policy = data.aws_iam_policy_document.config_aggregator_assume.json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "config_aggregator" {
  count = var.enable_config && var.is_organization ? 1 : 0

  role       = aws_iam_role.config_aggregator[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

# CM-8 at organization scale: one queryable inventory across every account and
# every region, instead of N console tabs. This is the resource that makes
# "show me every unencrypted volume in the boundary" a single query.
resource "aws_config_configuration_aggregator" "org" {
  count = var.enable_config && var.is_organization ? 1 : 0

  name = "${var.name_prefix}-org-aggregator"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator[0].arn
  }

  tags = local.tags

  depends_on = [aws_iam_role_policy_attachment.config_aggregator]
}

# ----------------------------------------------------------- conformance packs

# The packs below are trimmed, hand-maintained subsets of the AWS-published
# operational-best-practices templates. They are deliberately not the full
# published packs: the full FedRAMP pack is ~150 rules and several thousand
# lines of CloudFormation, which nobody reviews, and unreviewed rules generate
# unreviewed findings. Each rule here was chosen because a specific control in
# the mapped framework depends on it. See CONTROLS.md DET-006 for the caveat.
locals {
  conformance_packs = var.enable_config && var.enable_conformance_packs ? {
    fedramp = {
      name     = "${var.name_prefix}-fedramp"
      template = "${path.module}/templates/${var.conformance_pack_template}"
    }
    nist = {
      name     = "${var.name_prefix}-nist-800-53-r5"
      template = "${path.module}/templates/nist-800-53-r5.yaml"
    }
    cis = {
      name     = "${var.name_prefix}-cis-v5"
      template = "${path.module}/templates/cis-v5.yaml"
    }
  } : {}
}

resource "aws_config_conformance_pack" "account" {
  for_each = var.is_organization ? {} : local.conformance_packs

  name          = each.value.name
  template_body = file(each.value.template)

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_organization_conformance_pack" "org" {
  for_each = var.is_organization ? local.conformance_packs : {}

  name          = each.value.name
  template_body = file(each.value.template)

  depends_on = [
    aws_config_configuration_recorder_status.this,
    aws_config_configuration_aggregator.org,
  ]
}
