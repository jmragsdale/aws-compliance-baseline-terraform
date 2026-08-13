output "evidence_bucket_name" {
  description = "Name of the evidence lake bucket."
  value       = aws_s3_bucket.evidence.id
}

output "evidence_bucket_arn" {
  description = "ARN of the evidence lake bucket."
  value       = aws_s3_bucket.evidence.arn
}

output "firehose_stream_name" {
  description = "Name of the Firehose delivery stream carrying Security Hub findings."
  value       = aws_kinesis_firehose_delivery_stream.findings.name
}

output "glue_database_name" {
  description = "Glue database holding the findings table."
  value       = aws_glue_catalog_database.evidence.name
}

output "glue_table_name" {
  description = "Glue table auditors query."
  value       = aws_glue_catalog_table.findings.name
}

output "athena_workgroup_name" {
  description = "Athena workgroup for auditor queries."
  value       = aws_athena_workgroup.auditor.name
}

output "findings_dlq_url" {
  description = "URL of the dead letter queue for undeliverable findings."
  value       = aws_sqs_queue.findings_dlq.id
}
