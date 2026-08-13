# ---------------------------------------------------------------------------
# EventBridge -> Firehose -> partitioned S3.
#
# AU-7: raw findings are useless as evidence unless they can be reduced and
# reported on. The partitioning scheme below (year/month/day) is what makes an
# assessment-period query cheap; without it every question scans the entire
# lake and Athena bills accordingly.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "firehose" {
  name = "/aws/kinesisfirehose/${var.name_prefix}-findings"

  # 90 days, deliberately shorter than the AU-11 audit floor. These are delivery
  # diagnostics for the pipeline, not audit records -- the records themselves are
  # in the evidence bucket under Object Lock. policies/retention.rego carries the
  # same exemption for the same reason.
  # checkov:skip=CKV_AWS_338:Firehose delivery diagnostics are operational telemetry, not audit records. The audit records this pipeline carries are retained for the full baseline window in aws_s3_bucket.evidence under Object Lock.
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn

  tags = local.tags
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name               = "${var.name_prefix}-findings-firehose"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json

  tags = local.tags
}

# AC-6: this role writes to one bucket and one log stream. Nothing else.
data "aws_iam_policy_document" "firehose" {
  statement {
    sid    = "WriteEvidenceObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
    ]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid       = "WriteDeliveryLogs"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.firehose.arn}:log-stream:*"]
  }

  dynamic "statement" {
    for_each = local.use_cmk ? [1] : []

    content {
      sid       = "EncryptEvidence"
      effect    = "Allow"
      actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      resources = [var.kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "firehose" {
  name   = "${var.name_prefix}-findings-firehose"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose.json
}

resource "aws_kinesis_firehose_delivery_stream" "findings" {
  name        = "${var.name_prefix}-security-hub-findings"
  destination = "extended_s3"

  # checkov:skip=CKV_AWS_241:key_type is CUSTOMER_MANAGED_CMK whenever var.kms_key_arn is set (enable_customer_managed_keys). Checkov cannot evaluate the conditional; the AWS_OWNED_CMK fallback exists so the module still plans with CMKs off.

  # SC-28: encrypt the buffer in transit through Firehose, not just the objects
  # it lands. Findings sit in the buffer for up to 5 minutes.
  server_side_encryption {
    enabled  = true
    key_type = local.use_cmk ? "CUSTOMER_MANAGED_CMK" : "AWS_OWNED_CMK"
    key_arn  = var.kms_key_arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.evidence.arn

    # Hive-style partitions so Glue partition projection (see catalog.tf) can
    # infer them without a crawler running on a schedule.
    prefix              = "${local.findings_prefix}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "${local.findings_prefix}-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

    # Five minutes or 128 MB. Findings are not a real-time signal -- the alarms
    # in the logging module are -- so the larger buffer produces fewer, bigger
    # objects and materially cheaper Athena scans.
    buffering_interval = 300
    buffering_size     = 128

    compression_format = "GZIP"

    kms_key_arn = var.kms_key_arn

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }
  }

  tags = local.tags
}

# --------------------------------------------------------------- EventBridge

data "aws_iam_policy_document" "events_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "events_to_firehose" {
  name               = "${var.name_prefix}-findings-events"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json

  tags = local.tags
}

data "aws_iam_policy_document" "events_to_firehose" {
  statement {
    sid       = "PutFindingsToFirehose"
    effect    = "Allow"
    actions   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
    resources = [aws_kinesis_firehose_delivery_stream.findings.arn]
  }
}

resource "aws_iam_role_policy" "events_to_firehose" {
  name   = "${var.name_prefix}-findings-events"
  role   = aws_iam_role.events_to_firehose.id
  policy = data.aws_iam_policy_document.events_to_firehose.json
}

# CA-7: every finding, at every severity, including the ones that get
# suppressed. An assessor asking "how do you know this was suppressed
# deliberately" needs the suppressed ones in the record too.
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "${var.name_prefix}-security-hub-findings"
  description = "Streams every Security Hub finding to the evidence lake (CA-7, AU-7)"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "firehose" {
  rule     = aws_cloudwatch_event_rule.securityhub_findings.name
  arn      = aws_kinesis_firehose_delivery_stream.findings.arn
  role_arn = aws_iam_role.events_to_firehose.arn

  # AU-5: an event that cannot be delivered is a gap in the evidence record, so
  # failures are retried for a full day and then reported rather than dropped.
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }

  dead_letter_config {
    arn = aws_sqs_queue.findings_dlq.arn
  }
}

# AU-5: the dead letter queue is the audit trail of the audit trail. If it is
# non-empty, evidence was lost and somebody needs to know today.
resource "aws_sqs_queue" "findings_dlq" {
  name                      = "${var.name_prefix}-findings-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = !local.use_cmk
  kms_master_key_id         = var.kms_key_arn

  tags = local.tags
}

data "aws_iam_policy_document" "findings_dlq" {
  statement {
    sid       = "AllowEventBridgeDeadLetter"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.findings_dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.securityhub_findings.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.findings_dlq.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "findings_dlq" {
  queue_url = aws_sqs_queue.findings_dlq.id
  policy    = data.aws_iam_policy_document.findings_dlq.json
}

resource "aws_cloudwatch_metric_alarm" "findings_dlq_not_empty" {
  alarm_name          = "${var.name_prefix}-evidence-pipeline-dropping-findings"
  alarm_description   = "AU-5: findings failed delivery to the evidence lake and are sitting in the DLQ."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.findings_dlq.name }
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.alarm_topic_arn]

  tags = local.tags
}
