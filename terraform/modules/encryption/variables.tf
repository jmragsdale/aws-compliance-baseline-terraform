variable "name_prefix" {
  description = "Prefix for key aliases."
  type        = string
}

variable "tags" {
  description = "Tags applied to every key in this module."
  type        = map(string)
}

variable "rotation_days" {
  description = "Automatic key rotation period in days. AWS enforces a 90-day minimum."
  type        = number

  validation {
    condition     = var.rotation_days >= 90 && var.rotation_days <= 2560
    error_message = "rotation_days must be between 90 and 2560 (AWS KMS limits)."
  }
}

variable "multi_region" {
  description = "Create the logs and evidence keys as multi-Region primaries so a replica can exist in the DR region."
  type        = bool
  default     = false
}

variable "create_replica" {
  description = "Create the replica of the logs key in the aws.replica provider region."
  type        = bool
  default     = false
}

variable "organization_id" {
  description = "Organization ID used to scope key use to principals inside the org."
  type        = string
}

variable "log_archive_account_id" {
  description = "Account allowed to write audit records encrypted under the logs key."
  type        = string
}

variable "security_tooling_account_id" {
  description = "Delegated security administrator account, allowed to read evidence."
  type        = string
}

variable "deletion_window_days" {
  description = "Pending-deletion window. Long windows are deliberate: an accidental key deletion destroys the audit trail it protects."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_days >= 7 && var.deletion_window_days <= 30
    error_message = "deletion_window_days must be between 7 and 30."
  }
}
