output "baseline" {
  description = "Effective FedRAMP baseline and the parameters it selected. Useful as evidence of what was actually deployed."
  value = {
    label                    = local.bl.baseline_label
    deployment_scope         = var.deployment_scope
    audit_retention_days     = local.bl.object_lock_days
    log_group_retention_days = local.bl.cloudwatch_retention_days
    kms_rotation_days        = local.bl.kms_rotation_days
    cross_region_replication = local.bl.cross_region_replication
    require_kms_for_s3_put   = local.bl.require_kms_for_s3_put
    max_session_seconds      = local.bl.max_session_seconds
    minimum_password_length  = local.bl.password_min_length
    availability_zones       = local.availability_zone_count
  }
}

output "enabled_controls" {
  description = "Which control planes this deployment actually turned on."
  value = {
    preventive_guardrails = var.enable_preventive_guardrails
    central_logging       = local.logging_enabled
    customer_managed_keys = local.encryption_enabled
    config                = local.config_enabled
    conformance_packs     = local.config_enabled && var.enable_conformance_packs
    security_hub          = var.enable_security_hub
    guardduty             = var.enable_guardduty
    access_analyzer       = var.enable_access_analyzer
    macie                 = var.enable_macie
    inspector             = var.enable_inspector
    network_baseline      = local.network_enabled
    vpc_endpoints         = local.network_enabled && var.enable_vpc_endpoints
    evidence_lake         = local.evidence_enabled
  }
}

output "log_archive_bucket_name" {
  description = "Central log archive bucket, or null when central logging is off."
  value       = local.logging_enabled ? module.logging[0].log_archive_bucket_name : null
}

output "organization_trail_arn" {
  description = "ARN of the organization CloudTrail, or null."
  value       = local.logging_enabled ? module.logging[0].trail_arn : null
}

output "security_alarms_topic_arn" {
  description = "SNS topic every CIS monitoring alarm publishes to, or null."
  value       = local.logging_enabled ? module.logging[0].security_alarms_topic_arn : null
}

output "cis_monitoring_alarm_count" {
  description = "Number of CIS section 4 alarm/metric-filter pairs created."
  value       = local.logging_enabled ? module.logging[0].monitored_event_count : 0
}

output "scp_policy_ids" {
  description = "Service control policies created, keyed by theme."
  value       = var.enable_preventive_guardrails ? module.preventive[0].scp_ids : {}
}

output "rcp_policy_ids" {
  description = "Resource control policies created, keyed by theme."
  value       = var.enable_preventive_guardrails ? module.preventive[0].rcp_ids : {}
}

output "security_hub_standards" {
  description = "Security Hub standards subscribed to."
  value       = length(module.detective) > 0 ? module.detective[0].standards_subscribed : []
}

output "conformance_packs" {
  description = "AWS Config conformance packs deployed."
  value       = length(module.detective) > 0 ? module.detective[0].conformance_pack_names : []
}

output "evidence_query_target" {
  description = "Where an auditor points Athena. Feed these to scripts/export-evidence.sh."
  value = local.evidence_enabled ? {
    workgroup = module.evidence[0].athena_workgroup_name
    database  = module.evidence[0].glue_database_name
    table     = module.evidence[0].glue_table_name
    bucket    = module.evidence[0].evidence_bucket_name
  } : null
}

output "kms_key_arns" {
  description = "Customer-managed keys by data domain, or null when CMKs are off."
  value = local.encryption_enabled ? {
    logs         = module.encryption[0].logs_key_arn
    logs_replica = module.encryption[0].logs_replica_key_arn
    evidence     = module.encryption[0].evidence_key_arn
    general      = module.encryption[0].general_key_arn
  } : null
}

output "baseline_vpc_id" {
  description = "ID of the baseline VPC, or null when the network module is off."
  value       = local.network_enabled ? module.network[0].vpc_id : null
}
