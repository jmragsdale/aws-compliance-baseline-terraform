variable "name_prefix" {
  description = "Prefix for recorder, aggregator, analyzer and conformance pack names."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource in this module."
  type        = map(string)
}

variable "is_organization" {
  description = "Enable organization-scoped detective configuration (delegated admins, org aggregator, org conformance packs)."
  type        = bool
}

variable "security_tooling_account_id" {
  description = "Account delegated as administrator for each security service."
  type        = string
}

variable "log_archive_bucket_name" {
  description = "Bucket that AWS Config delivers snapshots and history to."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for Config delivery and Security Hub exports. Null falls back to service-managed encryption."
  type        = string
  default     = null
}

variable "config_delivery_frequency" {
  description = "Config snapshot delivery frequency. Baseline-driven: 24h at Moderate, 3h at High."
  type        = string

  validation {
    condition = contains(
      ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"],
      var.config_delivery_frequency
    )
    error_message = "config_delivery_frequency must be one of One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "guardduty_publishing_frequency" {
  description = "How often GuardDuty publishes updated findings to members. Baseline-driven."
  type        = string

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_publishing_frequency)
    error_message = "guardduty_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS."
  }
}

variable "unused_access_age_days" {
  description = "Age at which Access Analyzer reports an IAM principal or permission as unused. Baseline-driven (AC-6(7))."
  type        = number
}

variable "conformance_pack_template" {
  description = "Filename under templates/ selected by the FedRAMP baseline."
  type        = string
}

variable "target_ou_ids" {
  description = "Roots or OUs the Security Hub configuration policy is associated with. Empty in single-account mode."
  type        = list(string)
  default     = []
}

variable "aggregator_regions" {
  description = "Regions the Config aggregator and Security Hub finding aggregator pull from."
  type        = list(string)
}

variable "enable_config" {
  description = "Create the Config recorder, delivery channel and aggregator."
  type        = bool
  default     = false
}

variable "enable_conformance_packs" {
  description = "Deploy the FedRAMP, NIST 800-53 Rev 5 and CIS conformance packs."
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  description = "Enable Security Hub and subscribe to the CIS, NIST and FSBP standards."
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Enable GuardDuty with the S3, EKS, RDS and Lambda protection plans."
  type        = bool
  default     = false
}

variable "enable_guardduty_malware_protection" {
  description = "Enable GuardDuty EBS malware protection. Metered separately and considerably more expensive."
  type        = bool
  default     = false
}

variable "enable_access_analyzer" {
  description = "Create the external-access and unused-access analyzers."
  type        = bool
  default     = false
}

variable "enable_macie" {
  description = "Enable Macie for sensitive data discovery."
  type        = bool
  default     = false
}

variable "enable_inspector" {
  description = "Enable Inspector v2 for EC2, ECR and Lambda."
  type        = bool
  default     = false
}

variable "enable_inspector_lambda_code_scan" {
  description = "Add Inspector Lambda code scanning on top of standard Lambda scanning."
  type        = bool
  default     = false
}
