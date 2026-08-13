# ---------------------------------------------------------------------------
# Root composition.
#
# Ordering here is not cosmetic -- it is the dependency chain the controls
# themselves have:
#
#   encryption -> logging -> {preventive, detective, network, evidence}
#
# Keys before logs, because audit records that are not encrypted under a key we
# control are not protected (AU-9 / SC-28). Logs before the preventive layer,
# because the SCP that protects the archive needs the archive's ARN. Logs before
# everything else, because Config, flow logs and the evidence lake all deliver
# into the same bucket, under the same Object Lock window, so that one retention
# decision covers every kind of audit record instead of four.
#
# Each module is gated twice: once by its own enable_* switch (cost) and once by
# whether its prerequisites exist (correctness). A single_account plan with all
# switches off is a valid, empty, zero-cost plan.
# ---------------------------------------------------------------------------

locals {
  # Cost gates.
  encryption_enabled = var.enable_customer_managed_keys
  logging_enabled    = var.enable_central_logging

  # Correctness gates: these modules deliver into the log archive, so switching
  # them on without it would produce a plan that applies and then silently fails
  # to deliver anything.
  network_enabled  = var.enable_network_baseline && var.enable_central_logging
  evidence_enabled = var.enable_evidence_lake && var.enable_central_logging
  config_enabled   = var.enable_config && var.enable_central_logging

  logs_key_arn         = local.encryption_enabled ? module.encryption[0].logs_key_arn : null
  logs_replica_key_arn = local.encryption_enabled ? module.encryption[0].logs_replica_key_arn : null
  evidence_key_arn     = local.encryption_enabled ? module.encryption[0].evidence_key_arn : null
  general_key_arn      = local.encryption_enabled ? module.encryption[0].general_key_arn : null

  log_archive_bucket_arn  = local.logging_enabled ? module.logging[0].log_archive_bucket_arn : null
  log_archive_bucket_name = local.logging_enabled ? module.logging[0].log_archive_bucket_name : ""
  access_logs_bucket_name = local.logging_enabled ? module.logging[0].access_logs_bucket_name : ""
  alarm_topic_arn         = local.logging_enabled ? module.logging[0].security_alarms_topic_arn : ""
}

# CA-2/CA-7 sanity check surfaced at plan time rather than discovered during an
# assessment: claiming a FedRAMP High posture while the detective layer is off
# is the kind of thing that reads fine in a tfvars file and badly in an SSP.
check "high_baseline_completeness" {
  assert {
    condition = var.fedramp_baseline != "high" || (
      var.enable_central_logging && var.enable_config && var.enable_security_hub && var.enable_guardduty
    )
    error_message = "fedramp_baseline is \"high\" but central logging, Config, Security Hub or GuardDuty is disabled. The High baseline has no compliant configuration without all four."
  }
}

check "high_baseline_requires_customer_keys" {
  assert {
    condition     = var.fedramp_baseline != "high" || var.enable_customer_managed_keys
    error_message = "fedramp_baseline is \"high\" but enable_customer_managed_keys is false. SC-28(1) at High requires customer-managed keys, and the deny-unencrypted-PUT guardrail will reject SSE-S3 writes."
  }
}

# ---------------------------------------------------------------- encryption

module "encryption" {
  count = local.encryption_enabled ? 1 : 0

  source = "./modules/encryption"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  name_prefix                 = var.name_prefix
  tags                        = local.tags
  rotation_days               = local.bl.kms_rotation_days
  multi_region                = local.bl.kms_multi_region
  create_replica              = local.bl.cross_region_replication
  organization_id             = var.organization_id
  log_archive_account_id      = var.log_archive_account_id
  security_tooling_account_id = var.security_tooling_account_id
}

# ------------------------------------------------------------------- logging

module "logging" {
  count = local.logging_enabled ? 1 : 0

  source = "./modules/logging"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  name_prefix            = var.name_prefix
  tags                   = local.tags
  bucket_name            = local.log_archive_bucket_name_computed
  is_organization        = local.is_org
  organization_id        = var.organization_id
  log_archive_account_id = var.log_archive_account_id

  kms_key_arn         = local.logs_key_arn
  replica_kms_key_arn = local.logs_replica_key_arn

  object_lock_days             = local.bl.object_lock_days
  cloudwatch_retention_days    = local.bl.cloudwatch_retention_days
  glacier_transition_days      = local.bl.glacier_transition_days
  deep_archive_transition_days = local.bl.deep_archive_transition_days
  enable_replication           = local.bl.cross_region_replication
  enable_data_events           = var.enable_cloudtrail_data_events
  security_contact_email       = var.security_contact_email
}

# ---------------------------------------------------------------- preventive

module "preventive" {
  count = var.enable_preventive_guardrails ? 1 : 0

  source = "./modules/preventive"

  name_prefix     = var.name_prefix
  tags            = local.tags
  is_organization = local.is_org
  organization_id = var.organization_id
  target_ou_ids   = var.target_ou_ids
  allowed_regions = var.allowed_regions

  break_glass_account_id = var.management_account_id

  require_kms_for_s3_put = local.bl.require_kms_for_s3_put
  log_archive_bucket_arn = local.log_archive_bucket_arn

  password_min_length       = local.bl.password_min_length
  password_max_age_days     = local.bl.password_max_age_days
  password_reuse_prevention = local.bl.password_reuse_prevention

  ebs_default_kms_key_id = local.general_key_arn
}

# ----------------------------------------------------------------- detective

module "detective" {
  count = var.enable_security_hub || local.config_enabled || var.enable_guardduty || var.enable_access_analyzer || var.enable_macie || var.enable_inspector ? 1 : 0

  source = "./modules/detective"

  name_prefix                 = var.name_prefix
  tags                        = local.tags
  is_organization             = local.is_org
  security_tooling_account_id = var.security_tooling_account_id
  log_archive_bucket_name     = local.log_archive_bucket_name
  kms_key_arn                 = local.logs_key_arn
  target_ou_ids               = var.target_ou_ids

  config_delivery_frequency      = local.bl.config_delivery_frequency
  guardduty_publishing_frequency = local.bl.guardduty_publishing_frequency
  unused_access_age_days         = local.bl.unused_access_age_days
  conformance_pack_template      = local.bl.conformance_pack_template
  aggregator_regions             = var.allowed_regions

  enable_config                       = local.config_enabled
  enable_conformance_packs            = var.enable_conformance_packs
  enable_security_hub                 = var.enable_security_hub
  enable_guardduty                    = var.enable_guardduty
  enable_guardduty_malware_protection = var.enable_guardduty_malware_protection
  enable_access_analyzer              = var.enable_access_analyzer
  enable_macie                        = var.enable_macie
  enable_inspector                    = var.enable_inspector
  enable_inspector_lambda_code_scan   = var.enable_inspector_lambda_code_scan
}

# ------------------------------------------------------------------- network

module "network" {
  count = local.network_enabled ? 1 : 0

  source = "./modules/network"

  name_prefix                  = var.name_prefix
  tags                         = local.tags
  vpc_cidr                     = var.vpc_cidr
  availability_zone_count      = local.availability_zone_count
  log_archive_bucket_arn       = local.log_archive_bucket_arn
  flow_log_aggregation_seconds = local.bl.flow_log_aggregation_seconds
  enable_vpc_endpoints         = var.enable_vpc_endpoints
  organization_id              = var.organization_id
}

# ------------------------------------------------------------------ evidence

module "evidence" {
  count = local.evidence_enabled ? 1 : 0

  source = "./modules/evidence"

  name_prefix             = var.name_prefix
  tags                    = local.tags
  bucket_name             = local.evidence_bucket_name
  kms_key_arn             = local.evidence_key_arn
  access_logs_bucket_name = local.access_logs_bucket_name
  evidence_retention_days = local.bl.evidence_retention_days
  glacier_transition_days = local.bl.glacier_transition_days
  organization_id         = var.organization_id
  alarm_topic_arn         = local.alarm_topic_arn
}
