# ---------------------------------------------------------------------------
# Cross-region replication of the audit archive.
#
# Only created when the FedRAMP baseline demands it. CP-9 ("system backup") and
# CP-10 ("system recovery and reconstitution") are the drivers: at High, the
# loss of a region must not take the audit record with it. At Moderate the cost
# of a second full copy of every audit record is rarely justified, so the
# baseline table leaves it off.
#
# The replica carries its own Object Lock configuration. Replication copies
# objects, not bucket-level protections -- a replica without Object Lock is a
# deletable copy of an undeletable archive, which is worse than no replica
# because it looks like protection.
# ---------------------------------------------------------------------------

locals {
  replication_count = var.enable_replication ? 1 : 0
  use_replica_cmk   = var.replica_kms_key_arn != null
}

resource "aws_s3_bucket" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket              = local.replica_bucket_name
  force_destroy       = false
  object_lock_enabled = true

  # checkov:skip=CKV2_AWS_62:Same reasoning as the primary archive -- notifications per delivered object are noise nothing consumes.
  # checkov:skip=CKV_AWS_144:This bucket IS the cross-region replica. Replicating the replica is not a control, it is a loop.
  # checkov:skip=CKV_AWS_18:Access logging on the replica would require a second access-log bucket in the replica region for records nobody queries; the primary archive's access log covers auditor reads.
  tags = merge(local.tags, { Purpose = "audit-log-archive-replica" })
}

resource "aws_s3_bucket_public_access_block" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket = aws_s3_bucket.log_archive_replica[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket = aws_s3_bucket.log_archive_replica[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket = aws_s3_bucket.log_archive_replica[0].id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.log_archive_replica]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket = aws_s3_bucket.log_archive_replica[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.use_replica_cmk ? "aws:kms" : "AES256"
      kms_master_key_id = var.replica_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# AU-11: the replica inherits the retention decision, not just the objects. A
# replica that tiers differently from the primary means a recovery test finds
# records in Deep Archive that the primary still had in Standard, and the
# restore takes twelve hours instead of none.
resource "aws_s3_bucket_lifecycle_configuration" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket = aws_s3_bucket.log_archive_replica[0].id

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

    noncurrent_version_expiration {
      noncurrent_days = var.object_lock_days + 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "log_archive_replica" {
  count = local.replication_count

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log_archive_replica[0].arn, "${aws_s3_bucket.log_archive_replica[0].arn}/*"]

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
    sid    = "DenyArchiveTampering"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketVersioning",
    ]
    resources = [aws_s3_bucket.log_archive_replica[0].arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "log_archive_replica" {
  count = local.replication_count

  provider = aws.replica

  bucket = aws_s3_bucket.log_archive_replica[0].id
  policy = data.aws_iam_policy_document.log_archive_replica[0].json

  depends_on = [aws_s3_bucket_public_access_block.log_archive_replica]
}

data "aws_iam_policy_document" "replication_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  count = local.replication_count

  name               = "${var.name_prefix}-s3-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json

  tags = local.tags
}

# AC-6: the replication role can read from exactly one bucket and write to
# exactly one bucket. It is not a general S3 role.
data "aws_iam_policy_document" "replication" {
  count = local.replication_count

  statement {
    sid       = "ReadSourceBucket"
    effect    = "Allow"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.log_archive.arn]
  }

  statement {
    sid    = "ReadSourceObjects"
    effect = "Allow"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention",
      "s3:GetObjectLegalHold",
    ]
    resources = ["${aws_s3_bucket.log_archive.arn}/*"]
  }

  statement {
    sid    = "WriteReplicaObjects"
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner",
    ]
    resources = ["${aws_s3_bucket.log_archive_replica[0].arn}/*"]
  }

  dynamic "statement" {
    for_each = local.use_cmk ? [1] : []

    content {
      sid       = "DecryptSourceObjects"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:DescribeKey"]
      resources = [var.kms_key_arn]
    }
  }

  dynamic "statement" {
    for_each = local.use_replica_cmk ? [1] : []

    content {
      sid       = "EncryptReplicaObjects"
      effect    = "Allow"
      actions   = ["kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = [var.replica_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  count = local.replication_count

  name   = "${var.name_prefix}-s3-replication"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "log_archive" {
  count = local.replication_count

  bucket = aws_s3_bucket.log_archive.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id       = "replicate-audit-records"
    status   = "Enabled"
    priority = 0

    filter {}

    delete_marker_replication {
      # Replicating delete markers would let a deletion in the primary hide the
      # object in the replica, which defeats the point of having a replica.
      status = "Disabled"
    }

    destination {
      bucket        = aws_s3_bucket.log_archive_replica[0].arn
      storage_class = "STANDARD"

      dynamic "encryption_configuration" {
        for_each = local.use_replica_cmk ? [1] : []

        content {
          replica_kms_key_id = var.replica_kms_key_arn
        }
      }

      # CP-9: RPO is only meaningful if it is measured. RTC gives a 15-minute
      # replication SLA and emits metrics when it is missed.
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }

      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = local.use_cmk ? "Enabled" : "Disabled"
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.log_archive,
    aws_s3_bucket_versioning.log_archive_replica,
  ]
}
