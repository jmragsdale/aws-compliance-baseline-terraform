output "logs_key_arn" {
  description = "ARN of the audit log CMK."
  value       = aws_kms_key.logs.arn
}

output "logs_key_id" {
  description = "Key ID of the audit log CMK."
  value       = aws_kms_key.logs.key_id
}

output "logs_replica_key_arn" {
  description = "ARN of the replica audit log CMK in the DR region, or null when the baseline does not replicate."
  value       = try(aws_kms_replica_key.logs[0].arn, null)
}

output "evidence_key_arn" {
  description = "ARN of the compliance evidence CMK."
  value       = aws_kms_key.evidence.arn
}

output "general_key_arn" {
  description = "ARN of the general workload data CMK."
  value       = aws_kms_key.general.arn
}

output "general_key_id" {
  description = "Key ID of the general workload data CMK, used for EBS encryption-by-default."
  value       = aws_kms_key.general.key_id
}
