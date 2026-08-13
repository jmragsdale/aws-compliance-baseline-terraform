# ---------------------------------------------------------------------------
# Organization CloudTrail.
#
# AU-2 (event logging), AU-3 (content of audit records), AU-6 (review and
# analysis), AU-9 (protection of audit information) and AU-12 (audit record
# generation) all collapse onto this one resource plus its destinations.
# CIS AWS Foundations v5.0 section 3 states the same requirements as discrete
# checks: enabled in all regions, log file validation on, integrated with
# CloudWatch Logs, encrypted with a CMK.
#
# An *organization* trail is used rather than per-account trails because a
# member account cannot stop or reconfigure it -- the trail is owned by the
# management account. That property is what makes AU-9 real rather than
# aspirational, and it is why deployment_scope matters.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(local.tags, { Purpose = "cloudtrail-analysis" })
}

data "aws_iam_policy_document" "cloudtrail_cwl_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cwl" {
  name               = "${var.name_prefix}-cloudtrail-to-cwl"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cwl_assume.json

  tags = local.tags
}

# AC-6: this role may only append to the one log group it was created for. It
# is scoped to the log stream prefix CloudTrail actually uses.
data "aws_iam_policy_document" "cloudtrail_cwl" {
  statement {
    sid       = "WriteTrailEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cwl" {
  name   = "${var.name_prefix}-cloudtrail-to-cwl"
  role   = aws_iam_role.cloudtrail_cwl.id
  policy = data.aws_iam_policy_document.cloudtrail_cwl.json
}

resource "aws_cloudtrail" "org" {
  name           = "${var.name_prefix}-org-trail"
  s3_bucket_name = aws_s3_bucket.log_archive.id

  # CIS 3.1: a single trail covering every region. A regional trail leaves every
  # other region silently unaudited, which is exactly where unwanted activity
  # tends to appear.
  is_multi_region_trail = true

  # AU-2: IAM, STS, CloudFront and Route 53 are global services whose events are
  # only recorded when this is on.
  include_global_service_events = true

  # Only the management account (or a delegated CloudTrail administrator) can
  # set this, so single-account deployments fall back to an account trail.
  is_organization_trail = var.is_organization

  # AU-9(3): SHA-256 digest files, delivered hourly, let an assessor prove the
  # log files have not been altered since delivery. This is the difference
  # between "we have logs" and "we can prove these are the logs".
  enable_log_file_validation = true

  # SC-28: null here means SSE-S3 rather than a CMK; the CIS check for a
  # CMK-encrypted trail only passes when enable_customer_managed_keys is on.
  kms_key_id = var.kms_key_arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cwl.arn

  # AU-5: CloudTrail publishes a notification for every log file it delivers.
  # Subscribing something to this is the only way to distinguish "no activity"
  # from "delivery has silently stopped" without waiting for the absence alarm
  # in alarms.tf to trip three hours later.
  sns_topic_name = aws_sns_topic.security_alarms.name

  enable_logging = true

  # AU-2: management events, both read and write. Excluding read events is a
  # common cost optimisation that also removes the evidence of reconnaissance.
  advanced_event_selector {
    name = "management-events-all"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # AU-2 for object-level access. Metered separately and genuinely expensive on
  # busy accounts, so it is a switch rather than a default.
  dynamic "advanced_event_selector" {
    for_each = var.enable_data_events ? [1] : []

    content {
      name = "s3-object-data-events"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }

      # Recording the trail's own delivery writes would create a feedback loop
      # that costs money and tells you nothing.
      field_selector {
        field           = "resources.ARN"
        not_starts_with = ["${aws_s3_bucket.log_archive.arn}/"]
      }
    }
  }

  dynamic "advanced_event_selector" {
    for_each = var.enable_data_events ? [1] : []

    content {
      name = "lambda-invoke-data-events"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::Lambda::Function"]
      }
    }
  }

  depends_on = [
    aws_s3_bucket_policy.log_archive,
    aws_iam_role_policy.cloudtrail_cwl,
    aws_sns_topic_policy.security_alarms,
  ]

  tags = local.tags
}
