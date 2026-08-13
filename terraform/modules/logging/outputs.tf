output "log_archive_bucket_name" {
  description = "Name of the central log archive bucket."
  value       = aws_s3_bucket.log_archive.id
}

output "log_archive_bucket_arn" {
  description = "ARN of the central log archive bucket."
  value       = aws_s3_bucket.log_archive.arn
}

output "access_logs_bucket_name" {
  description = "Name of the S3 server access log bucket."
  value       = aws_s3_bucket.access_logs.id
}

output "replica_bucket_arn" {
  description = "ARN of the replicated archive, or null when the baseline does not replicate."
  value       = try(aws_s3_bucket.log_archive_replica[0].arn, null)
}

output "trail_arn" {
  description = "ARN of the organization CloudTrail."
  value       = aws_cloudtrail.org.arn
}

output "trail_log_group_name" {
  description = "CloudWatch Logs group receiving trail events."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "security_alarms_topic_arn" {
  description = "SNS topic every CIS monitoring alarm publishes to."
  value       = aws_sns_topic.security_alarms.arn
}

output "monitored_event_count" {
  description = "Number of CIS section 4 metric filter / alarm pairs created."
  value       = length(local.monitored_events)
}
