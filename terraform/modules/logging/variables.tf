variable "name_prefix" {
  description = "Prefix for bucket, trail, log group and topic names."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource in this module."
  type        = map(string)
}

variable "bucket_name" {
  description = "Globally unique name for the central log archive bucket."
  type        = string
}

variable "is_organization" {
  description = "Create the trail as an organization trail. Requires the management account or a delegated CloudTrail administrator."
  type        = bool
}

variable "organization_id" {
  description = "Organization ID used in the bucket policy path conditions and the perimeter deny."
  type        = string
}

variable "log_archive_account_id" {
  description = "Account that owns the archive. Used to build the CloudTrail org prefix condition."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for the trail, log group, topic and bucket. Null falls back to SSE-S3 and AWS-managed keys."
  type        = string
  default     = null
}

variable "replica_kms_key_arn" {
  description = "CMK in the replica region used by the replication configuration. Null falls back to SSE-S3 on the replica."
  type        = string
  default     = null
}

variable "object_lock_days" {
  description = "Object Lock COMPLIANCE-mode retention in days. AU-11 drives this; the value comes from the FedRAMP baseline."
  type        = number

  validation {
    condition     = var.object_lock_days >= 1
    error_message = "object_lock_days must be at least 1."
  }
}

variable "cloudwatch_retention_days" {
  description = "CloudWatch Logs retention for the trail log group. Must be a value CloudWatch accepts."
  type        = number

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.cloudwatch_retention_days
    )
    error_message = "cloudwatch_retention_days must be one of the retention values CloudWatch Logs accepts."
  }
}

variable "glacier_transition_days" {
  description = "Days before archived audit records move to Glacier Instant Retrieval."
  type        = number
}

variable "deep_archive_transition_days" {
  description = "Days before archived audit records move to Glacier Deep Archive."
  type        = number
}

variable "enable_replication" {
  description = "Replicate the archive to the replica region. Driven by the FedRAMP baseline (High replicates, Moderate does not)."
  type        = bool
  default     = false
}

variable "enable_data_events" {
  description = "Record S3 object-level and Lambda invoke data events on the trail."
  type        = bool
  default     = false
}

variable "security_contact_email" {
  description = "Optional email subscribed to the alarm topic. Empty string creates no subscription."
  type        = string
  default     = ""
}

variable "alarm_namespace" {
  description = "CloudWatch namespace for the CIS metric filters."
  type        = string
  default     = "ComplianceBaseline"
}
