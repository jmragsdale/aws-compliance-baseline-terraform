output "scp_ids" {
  description = "Map of service control policy key to policy id."
  value       = { for k, v in local.scps : k => v.id }
}

output "rcp_ids" {
  description = "Map of resource control policy key to policy id."
  value       = { for k, v in local.rcps : k => v.id }
}

output "scp_attachment_count" {
  description = "Number of (policy, target) SCP attachments created."
  value       = length(local.scp_attachments)
}

output "rcp_attachment_count" {
  description = "Number of (policy, target) RCP attachments created."
  value       = length(local.rcp_attachments)
}

output "account_public_access_block_id" {
  description = "Account-level S3 Block Public Access resource id."
  value       = aws_s3_account_public_access_block.this.id
}
