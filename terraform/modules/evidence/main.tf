# ---------------------------------------------------------------------------
# Evidence lake.
#
# The gap this closes: Security Hub retains findings for 90 days. A FedRAMP
# assessment asks what your posture looked like across the whole authorisation
# period, and continuous monitoring (CA-7) means monthly evidence for the life
# of the ATO. Ninety days of console history does not answer either question.
#
# So every finding is streamed out as it is generated, landed in partitioned
# S3 under the same Object Lock discipline as the audit logs, and exposed
# through Glue and Athena as a table an auditor can query directly. AU-7
# (audit record reduction and report generation) is the control; being able to
# answer "show me every critical finding that was open for more than 30 days in
# Q3" without a support ticket is the point.
#
# EventBridge -> Firehose -> S3 -> Glue -> Athena. No Lambda, because a
# transform function is one more thing to patch, and Firehose dynamic
# partitioning already does what a transform would have been written for.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  tags = merge(var.tags, { Module = "evidence" })

  use_cmk = var.kms_key_arn != null

  findings_prefix = "security-hub-findings"
  athena_results  = "athena-results"
}

resource "aws_s3_bucket" "evidence" {
  bucket        = var.bucket_name
  force_destroy = false

  # AU-9: the same reasoning as the log archive. Evidence that can be edited is
  # not evidence.
  object_lock_enabled = true

  # checkov:skip=CKV2_AWS_62:Findings arrive through EventBridge, which is already the notification path. A second S3 event notification on the same data would duplicate every record downstream.
  # checkov:skip=CKV_AWS_144:The evidence lake is a derived artefact rebuildable from the log archive (which IS replicated at High). Paying twice for cross-region copies of derived data was a conscious cost trade-off.
  tags = merge(local.tags, { Purpose = "compliance-evidence" })
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_cmk ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  target_bucket = var.access_logs_bucket_name
  target_prefix = "evidence/"
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  # Findings stay in Standard while they are queried during an assessment, then
  # tier down. Athena can read Glacier Instant Retrieval directly, so tiering
  # does not break the auditor's queries.
  rule {
    id     = "findings-tiering"
    status = "Enabled"

    filter {
      prefix = "${local.findings_prefix}/"
    }

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.evidence_retention_days + 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Athena spill results are not evidence and should not accumulate for years.
  rule {
    id     = "expire-athena-results"
    status = "Enabled"

    filter {
      prefix = "${local.athena_results}/"
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  # Unfiltered catch-all. Firehose uploads findings in multipart chunks; a
  # failed upload leaves parts that are billable, invisible in the console
  # object list, and not covered by either prefixed rule above.
  rule {
    id     = "abort-failed-uploads-everywhere"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "evidence" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]

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

  statement {
    sid       = "DenyPrincipalsOutsideOrganization"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
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

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence.json

  depends_on = [aws_s3_bucket_public_access_block.evidence]
}
