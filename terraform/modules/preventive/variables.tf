variable "name_prefix" {
  description = "Prefix for policy names."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource in this module."
  type        = map(string)
}

variable "is_organization" {
  description = "Create and attach Organizations policies. False leaves only the account-level hardening resources."
  type        = bool
}

variable "organization_id" {
  description = "Organization ID used in data perimeter conditions."
  type        = string
}

variable "target_ou_ids" {
  description = "Roots or OUs that every policy in this module attaches to."
  type        = list(string)
  default     = []
}

variable "allowed_regions" {
  description = "Regions the organization may operate in."
  type        = list(string)
}

variable "require_kms_for_s3_put" {
  description = "Reject S3 PUTs that are not encrypted with aws:kms. FedRAMP High sets this; Moderate also accepts AES256."
  type        = bool
  default     = false
}

variable "log_archive_bucket_arn" {
  description = "ARN of the central log archive bucket. Null omits the archive-protection statement from the audit guardrail."
  type        = string
  default     = null
}

variable "break_glass_account_id" {
  description = <<-EOT
    Account that owns the break-glass roles. The deny guardrails exempt these
    roles ONLY in this account -- a wildcard account in the exemption ARN would
    let a role of the same name in any member account bypass every SCP in the
    organization, which is the opposite of a guardrail. AC-6(9), AC-2(7).
  EOT
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.break_glass_account_id))
    error_message = "break_glass_account_id must be a 12-digit AWS account ID."
  }
}

variable "break_glass_role_names" {
  description = <<-EOT
    IAM role names exempted from the deny guardrails so the organization can
    recover from a policy that locks everyone out. Every production SCP set
    needs one of these and every one of them needs to be alarmed on.
  EOT
  type        = list(string)
  default     = ["OrganizationBreakGlass"]
}

variable "password_min_length" {
  description = "Minimum IAM console password length."
  type        = number
}

variable "password_max_age_days" {
  description = "Maximum IAM console password age in days."
  type        = number
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords IAM remembers."
  type        = number
}

variable "ebs_default_kms_key_id" {
  description = "CMK used for EBS encryption-by-default. Null leaves the AWS-managed aws/ebs key in place."
  type        = string
  default     = null
}
