output "security_hub_enabled" {
  description = "Whether Security Hub was enabled in this deployment."
  value       = var.enable_security_hub
}

output "standards_subscribed" {
  description = "Security Hub standards ARNs this deployment subscribes to."
  value       = var.enable_security_hub ? values(local.standards_arns) : []
}

output "config_recorder_name" {
  description = "Name of the Config configuration recorder, or null when Config is off."
  value       = try(aws_config_configuration_recorder.this[0].name, null)
}

output "config_aggregator_arn" {
  description = "ARN of the organization Config aggregator, or null."
  value       = try(aws_config_configuration_aggregator.org[0].arn, null)
}

output "conformance_pack_names" {
  description = "Names of the conformance packs deployed."
  value       = [for k, v in local.conformance_packs : v.name]
}

output "guardduty_detector_id" {
  description = "GuardDuty detector id, or null when GuardDuty is off."
  value       = try(aws_guardduty_detector.this[0].id, null)
}

output "guardduty_features_enabled" {
  description = "GuardDuty protection plans switched on."
  value       = keys(local.guardduty_features)
}

output "access_analyzer_arns" {
  description = "ARNs of the external-access and unused-access analyzers."
  value = compact([
    try(aws_accessanalyzer_analyzer.external[0].arn, ""),
    try(aws_accessanalyzer_analyzer.unused[0].arn, ""),
  ])
}
