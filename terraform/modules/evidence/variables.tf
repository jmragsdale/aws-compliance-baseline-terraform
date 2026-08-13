variable "name_prefix" {
  description = "Prefix for bucket, stream, database and workgroup names."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource in this module."
  type        = map(string)
}

variable "bucket_name" {
  description = "Globally unique name for the evidence lake bucket."
  type        = string
}

variable "kms_key_arn" {
  description = "Evidence CMK. Null falls back to SSE-S3 and service-managed Firehose encryption."
  type        = string
  default     = null
}

variable "access_logs_bucket_name" {
  description = "Bucket receiving S3 server access logs for the evidence lake."
  type        = string
}

variable "evidence_retention_days" {
  description = "How long finding records are retained. Baseline-driven (AU-11)."
  type        = number
}

variable "glacier_transition_days" {
  description = "Days before evidence objects move to Glacier Instant Retrieval."
  type        = number
}

variable "organization_id" {
  description = "Organization ID used in the bucket perimeter condition."
  type        = string
}

variable "alarm_topic_arn" {
  description = "SNS topic notified when the evidence pipeline itself fails (AU-5)."
  type        = string
}

variable "athena_bytes_scanned_cutoff" {
  description = "Per-query byte ceiling for the auditor workgroup. Stops one unpartitioned SELECT * costing four figures."
  type        = number
  default     = 10737418240

  validation {
    condition     = var.athena_bytes_scanned_cutoff >= 10485760
    error_message = "athena_bytes_scanned_cutoff must be at least 10485760 (10 MB), the Athena minimum."
  }
}
