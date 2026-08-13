data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# The baseline table.
#
# FedRAMP Moderate and High differ far less in *which* controls apply than in
# *how strictly* they are parameterised. Keeping the difference in one lookup
# map means the two baselines share a single code path: there is exactly one
# place to read to answer "what changes at High?", and no conditional can drift
# out of sync with the others because there are no scattered conditionals.
#
# Sources for the values, so a reviewer can argue with them:
#   AU-11  audit record retention        -> retention_days / object_lock_days
#   SC-12  cryptographic key management  -> kms_rotation_days, kms_multi_region
#   SC-28  protection of data at rest    -> require_kms_for_s3_put
#   CP-9   system backup                 -> cross_region_replication
#   CP-10  system recovery               -> min_availability_zones
#   AC-11  session termination           -> max_session_seconds
#   IA-5   authenticator management      -> password_* values
#   SI-4   system monitoring              -> guardduty/config frequencies
#   AC-6   least privilege               -> unused_access_age_days
# ---------------------------------------------------------------------------

locals {
  baseline = {
    moderate = {
      # AU-11: one year of online audit records is the floor most Moderate
      # SSPs commit to. CloudWatch only accepts a fixed set of retention values.
      cloudwatch_retention_days = 365
      object_lock_days          = 365
      evidence_retention_days   = 365

      # AU-9(2)/CP-9: Moderate accepts a single-region archive with versioning
      # and Object Lock. High does not.
      cross_region_replication = false
      kms_multi_region         = false

      # SC-12(1): annual rotation is the documented default.
      kms_rotation_days = 365

      # SC-28: any AWS-managed server-side encryption satisfies Moderate, so the
      # deny-unencrypted-PUT SCP accepts AES256 as well as aws:kms.
      require_kms_for_s3_put = false

      # AC-11(1) / AC-12: 12h maximum federated session.
      max_session_seconds = 43200

      # IA-5(1).
      password_min_length       = 14
      password_max_age_days     = 90
      password_reuse_prevention = 24

      # SI-4: detection latency. Six-hour publishing is the GuardDuty default
      # and keeps EventBridge/Firehose volume predictable.
      guardduty_publishing_frequency = "SIX_HOURS"
      config_delivery_frequency      = "TwentyFour_Hours"

      # AC-6(7): how stale an IAM principal may be before Access Analyzer
      # raises an unused-access finding.
      unused_access_age_days = 90

      # CP-10: two AZs.
      min_availability_zones = 2

      # AU-6: flow log aggregation window. Ten minutes at Moderate.
      flow_log_aggregation_seconds = 600

      # Storage tiering. Moderate can afford to sit in Standard longer.
      glacier_transition_days      = 90
      deep_archive_transition_days = 365

      conformance_pack_template = "fedramp-moderate.yaml"
      baseline_label            = "FedRAMP Moderate"
    }

    high = {
      # AU-11: High baselines routinely commit to multi-year online retention.
      cloudwatch_retention_days = 1827
      object_lock_days          = 2555
      evidence_retention_days   = 1827

      # CP-9(1)/CP-10: audit records must survive the loss of a region.
      cross_region_replication = true
      kms_multi_region         = true

      # SC-12(1): quarterly rotation.
      kms_rotation_days = 90

      # SC-28(1): AES256 (SSE-S3) is not sufficient at High -- the PUT must name
      # a KMS key so key access is itself auditable and revocable.
      require_kms_for_s3_put = true

      # AC-11(1)/AC-12: one hour.
      max_session_seconds = 3600

      password_min_length       = 20
      password_max_age_days     = 60
      password_reuse_prevention = 24

      guardduty_publishing_frequency = "FIFTEEN_MINUTES"
      config_delivery_frequency      = "Three_Hours"

      unused_access_age_days = 45

      min_availability_zones = 3

      flow_log_aggregation_seconds = 60

      glacier_transition_days      = 30
      deep_archive_transition_days = 180

      conformance_pack_template = "fedramp-high.yaml"
      baseline_label            = "FedRAMP High"
    }
  }

  # Single dereference used everywhere downstream.
  bl = local.baseline[var.fedramp_baseline]

  is_org = var.deployment_scope == "organization"

  account_id = data.aws_caller_identity.current.account_id

  # Bucket names must be globally unique; the account id suffix is the standard
  # trick and is not sensitive on its own.
  log_archive_bucket_name_computed = "${var.name_prefix}-log-archive-${local.account_id}-${var.primary_region}"
  evidence_bucket_name             = "${var.name_prefix}-evidence-${local.account_id}-${var.primary_region}"

  # CP-10 floor: the High baseline overrides a too-small AZ count rather than
  # failing the plan, so a Moderate tfvars file can be promoted to High without
  # editing unrelated inputs.
  availability_zone_count = max(var.availability_zone_count, local.bl.min_availability_zones)

  common_tags = merge(
    {
      Project            = "aws-compliance-baseline"
      ManagedBy          = "terraform"
      ComplianceBaseline = local.bl.baseline_label
      DeploymentScope    = var.deployment_scope
      DataClassification = var.data_classification
    },
    var.tags,
  )

  tags = local.common_tags
}
