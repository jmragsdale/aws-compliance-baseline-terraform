# ---------------------------------------------------------------------------
# Central log archive.
#
# This bucket is the evidentiary spine of the whole baseline. AU-9 ("protect
# audit information from unauthorised access, modification and deletion") is not
# satisfied by an S3 bucket alone -- it is satisfied by versioning plus Object
# Lock in COMPLIANCE mode plus a bucket policy that even the account root cannot
# talk its way around plus a deny SCP on the account that owns it. All four are
# here; remove any one and the control is decorative.
#
# CIS AWS Foundations v5.0 sections 3.x cover the same ground from the other
# direction: trail enabled in all regions, log file validation on, logs
# encrypted with a CMK, bucket not public, access logging on the bucket.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  tags = merge(var.tags, { Module = "logging" })

  use_cmk = var.kms_key_arn != null

  # CloudTrail writes org trails under a prefix that includes the org id; the
  # single-account shape writes under the account id. Getting this wrong is the
  # classic reason a trail silently fails to deliver.
  trail_prefix = var.is_organization ? "AWSLogs/${var.organization_id}" : "AWSLogs/${local.account_id}"

  access_logs_bucket_name = "${var.bucket_name}-access"
  replica_bucket_name     = "${var.bucket_name}-replica"
}

# ------------------------------------------------------- server access logging

# CIS 3.x and AU-2: reads and writes against the audit archive are themselves
# audit events. Without this, someone who can read the archive leaves no trace.
resource "aws_s3_bucket" "access_logs" {
  bucket        = local.access_logs_bucket_name
  force_destroy = false

  # checkov:skip=CKV_AWS_145:S3 server access log delivery cannot write into a bucket whose default encryption is a customer-managed KMS key -- the logging.s3.amazonaws.com principal has no grant on it and delivery fails silently. SSE-S3 is the only option AWS supports here.
  # checkov:skip=CKV2_AWS_62:Event notifications on the access-log bucket would fire on every log delivery. Nothing consumes them and the volume is significant.
  # checkov:skip=CKV_AWS_144:The access-log bucket is deliberately single-region. Replicating S3 access logs to a second region doubles storage cost for a low-value secondary artefact; the audit records themselves (aws_s3_bucket.log_archive) are replicated at the High baseline.
  # checkov:skip=CKV_AWS_18:This bucket IS the access-log target. Pointing its access logging at itself creates an unbounded recursion of log deliveries.
  tags = merge(local.tags, { Purpose = "s3-access-logs" })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    # BucketOwnerEnforced disables ACLs entirely, which is the only way to make
    # "no public ACL" a structural property rather than a thing to keep checking.
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      # S3 server access logging cannot deliver into a bucket encrypted with a
      # customer-managed key unless the key grants the logging service; SSE-S3
      # keeps delivery reliable. The records here contain no payload data.
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.object_lock_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "access_logs" {
  # SC-8: unencrypted transport is refused outright rather than merely
  # discouraged. Every bucket in this repo carries this statement.
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]

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
    sid       = "S3ServerAccessLogsDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs.json

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

# --------------------------------------------------------------- log archive

resource "aws_s3_bucket" "log_archive" {
  bucket = var.bucket_name

  # AU-9: the archive must not be destroyable by the same automation that
  # created it. force_destroy stays false and Object Lock backs it up.
  force_destroy = false

  # Object Lock can only be turned on at creation time. This is the single most
  # common irreversible mistake in a compliance bucket build.
  object_lock_enabled = true

  # checkov:skip=CKV2_AWS_62:S3 event notifications on the archive are not used. Detection of tampering comes from CloudTrail data events plus the CIS alarms (LOG-010), not from bucket notifications, and a notification per delivered log object is high-volume noise.
  # checkov:skip=CKV_AWS_144:Cross-region replication is controlled by var.enable_replication, which the FedRAMP High baseline sets to true (see aws_s3_bucket_replication_configuration.log_archive). Checkov cannot see a conditionally-created replication configuration.
  tags = merge(local.tags, { Purpose = "audit-log-archive" })
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# AU-9 and CP-9: versioning is a prerequisite for both Object Lock and
# replication. Without it an overwrite is indistinguishable from a legitimate
# update and there is nothing to replicate.
resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

# AU-9(3)/AU-11: COMPLIANCE mode means no principal -- including the account
# root and including AWS Support -- can shorten the retention or delete the
# object version before it expires. GOVERNANCE mode would be a suggestion.
resource "aws_s3_bucket_object_lock_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.log_archive]
}

# SC-28 / CIS 3.x: audit records at rest are encrypted with a customer-managed
# key when one exists, so the ability to read them is revocable independently of
# the bucket policy.
resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_cmk ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    # Bucket keys cut KMS request cost by orders of magnitude on log workloads
    # without weakening the envelope encryption.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "log-archive/"
}

# AU-11 vs cost: records stay queryable in Standard for the first tier, then
# tier down. The lifecycle never expires objects earlier than the Object Lock
# window, because S3 would simply refuse the delete and generate noise.
resource "aws_s3_bucket_lifecycle_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    id     = "audit-record-tiering"
    status = "Enabled"

    filter {}

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = var.deep_archive_transition_days
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = var.object_lock_days + 1
    }

    noncurrent_version_transition {
      noncurrent_days = var.glacier_transition_days
      storage_class   = "GLACIER_IR"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.object_lock_days + 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "log_archive" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log_archive.arn, "${aws_s3_bucket.log_archive.arn}/*"]

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

  # SC-8(1): TLS 1.2 is the FedRAMP floor. Deny anything negotiated below it.
  statement {
    sid       = "DenyOutdatedTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log_archive.arn, "${aws_s3_bucket.log_archive.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }

  # AU-9: the archive cannot be dismantled. Note that this deliberately blocks
  # `terraform destroy` of the bucket -- see CONTROLS.md LOG-004 for the
  # break-glass procedure.
  statement {
    sid    = "DenyArchiveTampering"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketObjectLockConfiguration",
    ]
    resources = [aws_s3_bucket.log_archive.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  # CloudTrail's two required statements. The s3:x-amz-acl condition is what
  # AWS documents; without it delivery fails with a bare AccessDenied.
  statement {
    sid       = "CloudTrailBucketAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_archive.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id, var.log_archive_account_id]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/${local.trail_prefix}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # AWS Config delivers its configuration snapshots and history here so that
  # CM-8 (system component inventory) has a durable record, not just the
  # 7-year-rolling console view.
  statement {
    sid       = "ConfigBucketPermissions"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.log_archive.arn]

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

  statement {
    sid       = "ConfigWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # VPC flow logs land in the same archive so network and API audit records
  # share one retention and one Object Lock window (AU-2, AU-11).
  statement {
    sid       = "FlowLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/vpc-flow-logs/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "FlowLogDeliveryAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_archive.arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # Data perimeter (SC-7): no principal outside the organization reads the
  # archive, whatever an IAM policy elsewhere may say. Service principals are
  # exempted because CloudTrail and Config call with no PrincipalOrgID.
  statement {
    sid       = "DenyPrincipalsOutsideOrganization"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log_archive.arn, "${aws_s3_bucket.log_archive.arn}/*"]

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

resource "aws_s3_bucket_policy" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  policy = data.aws_iam_policy_document.log_archive.json

  depends_on = [aws_s3_bucket_public_access_block.log_archive]
}
