# ---------------------------------------------------------------------------
# Deployment shape
#
# Two variables decide almost everything about what this root module produces:
# how strict the parameters are (fedramp_baseline) and how much of the
# organization we are allowed to touch (deployment_scope). Everything else is
# an on/off switch for a metered service.
# ---------------------------------------------------------------------------

variable "fedramp_baseline" {
  description = <<-EOT
    FedRAMP Rev 5 baseline to parameterise the deployment against.

    This is not cosmetic. It drives audit-record retention (AU-11), key rotation
    period (SC-12), session and password strictness (AC-11 / IA-5), whether audit
    records are replicated to a second region (CP-9 / CP-10), and whether S3 PUTs
    must use a customer-managed KMS key rather than any server-side encryption
    (SC-28). See local.baseline in locals.tf for the full parameter table.
  EOT
  type        = string
  default     = "moderate"

  validation {
    condition     = contains(["moderate", "high"], var.fedramp_baseline)
    error_message = "fedramp_baseline must be \"moderate\" or \"high\"."
  }
}

variable "deployment_scope" {
  description = <<-EOT
    "organization" deploys org-owned controls (SCPs, RCPs, the organization
    CloudTrail, delegated administrators, the Config aggregator, org-scoped
    Access Analyzer). Those calls only succeed from an Organizations management
    account, so "single_account" gates them off and leaves the account-local
    controls, which is what the examples/single-account shape uses.
  EOT
  type        = string
  default     = "organization"

  validation {
    condition     = contains(["organization", "single_account"], var.deployment_scope)
    error_message = "deployment_scope must be \"organization\" or \"single_account\"."
  }
}

variable "name_prefix" {
  description = "Prefix for every resource name. Keep it short; S3 bucket names are built from it."
  type        = string
  default     = "compliance-baseline"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name_prefix))
    error_message = "name_prefix must be lowercase alphanumeric with hyphens, 3-31 characters, starting with a letter."
  }
}

variable "primary_region" {
  description = "Home region. The organization trail, Security Hub aggregator and log archive live here."
  type        = string
  default     = "us-east-1"
}

variable "replica_region" {
  description = <<-EOT
    Second region used for audit-record replication and the KMS replica key.
    Only consumed when the baseline requires cross-region replication (High), but
    the aliased provider must exist regardless so the module call always resolves.
  EOT
  type        = string
  default     = "us-west-2"
}

# ---------------------------------------------------------------------------
# Organization topology
#
# Placeholders only. Never commit real account IDs to a public repo -- an
# account ID is not a secret but it is free reconnaissance.
# ---------------------------------------------------------------------------

variable "management_account_id" {
  description = "Organizations management account ID. Placeholder by default."
  type        = string
  default     = "111111111111"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be a 12-digit AWS account ID."
  }
}

variable "log_archive_account_id" {
  description = "Account that owns the central log archive bucket (Control Tower calls this Log Archive)."
  type        = string
  default     = "111111111111"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.log_archive_account_id))
    error_message = "log_archive_account_id must be a 12-digit AWS account ID."
  }
}

variable "security_tooling_account_id" {
  description = <<-EOT
    Account delegated as administrator for Security Hub, GuardDuty, Config,
    Macie, Inspector and Access Analyzer. NIST 800-53 AC-5 (separation of duties)
    is the reason detective tooling does not live in the management account.
  EOT
  type        = string
  default     = "111111111111"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.security_tooling_account_id))
    error_message = "security_tooling_account_id must be a 12-digit AWS account ID."
  }
}

variable "organization_id" {
  description = "AWS Organizations ID (o-xxxxxxxxxx). Used in resource policy conditions to build the data perimeter."
  type        = string
  default     = "o-exampleorgid"
}

variable "target_ou_ids" {
  description = <<-EOT
    OU (or root) IDs that every service control policy and resource control
    policy is attached to. Attaching at the root is the usual production choice;
    attaching to a sandbox OU first is the usual safe rollout.
  EOT
  type        = list(string)
  default     = ["r-exam"]
}

variable "allowed_regions" {
  description = <<-EOT
    Regions the organization is permitted to operate in. Backs the region
    allow-list SCP, which is the cheapest way to satisfy the "operate only in
    authorized locations" expectation in a FedRAMP boundary (CA-9 / SC-7) and to
    stop shadow workloads appearing in unmonitored regions.
  EOT
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]

  validation {
    condition     = length(var.allowed_regions) > 0
    error_message = "allowed_regions must contain at least one region."
  }
}

variable "security_contact_email" {
  description = "Optional address subscribed to the security alarm topic. Empty string creates no subscription."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Feature switches
#
# Every switch below turns on a metered service. They default to false so a
# `plan` against a fresh account costs nothing and surprises nobody. The
# examples/ directory shows the intended production combinations.
# ---------------------------------------------------------------------------

variable "enable_preventive_guardrails" {
  description = "SCPs, RCPs and the account-level hardening baseline. Not metered, so this one defaults on."
  type        = bool
  default     = true
}

variable "enable_central_logging" {
  description = "Central log archive bucket, organization CloudTrail, CIS metric filters and alarms. Metered (S3, CloudTrail, CloudWatch)."
  type        = bool
  default     = false
}

variable "enable_cloudtrail_data_events" {
  description = "S3 object-level and Lambda invoke data events on the org trail. Materially increases CloudTrail cost on busy accounts."
  type        = bool
  default     = false
}

variable "enable_customer_managed_keys" {
  description = "Create per-domain KMS CMKs. Metered per key per month plus request charges; without it the baseline falls back to SSE-S3."
  type        = bool
  default     = false
}

variable "enable_config" {
  description = "AWS Config recorder, delivery channel and organization aggregator. Metered per configuration item."
  type        = bool
  default     = false
}

variable "enable_conformance_packs" {
  description = "Config conformance packs (FedRAMP, NIST 800-53 Rev 5, CIS). Metered per rule evaluation; requires enable_config."
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  description = "Security Hub with org auto-enable and the CIS / NIST / FSBP standards. Metered per check and per ingested finding."
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "GuardDuty organization-wide with the protection plans below. Metered per GB of analysed events."
  type        = bool
  default     = false
}

variable "enable_guardduty_malware_protection" {
  description = "GuardDuty Malware Protection for EC2 (EBS snapshot scanning). Separately metered and by far the most expensive plan."
  type        = bool
  default     = false
}

variable "enable_access_analyzer" {
  description = "IAM Access Analyzer external-access and unused-access analyzers. Unused-access findings are metered per IAM role or user analysed."
  type        = bool
  default     = false
}

variable "enable_macie" {
  description = "Macie sensitive-data discovery. Metered per GB inspected; leave off unless you have S3 data to classify."
  type        = bool
  default     = false
}

variable "enable_inspector" {
  description = "Inspector v2 for EC2, ECR, Lambda and Lambda code. Metered per resource scanned."
  type        = bool
  default     = false
}

variable "enable_network_baseline" {
  description = "Baseline VPC with private-only subnets and flow logs to the archive. Metered (flow log delivery)."
  type        = bool
  default     = false
}

variable "enable_vpc_endpoints" {
  description = "Interface endpoints for KMS/logs/STS/monitoring plus S3 and DynamoDB gateways. Interface endpoints are metered per hour per AZ."
  type        = bool
  default     = false
}

variable "enable_evidence_lake" {
  description = "Security Hub findings -> EventBridge -> Firehose -> partitioned S3 -> Glue/Athena. Metered (Firehose ingestion, Athena scans)."
  type        = bool
  default     = false
}

variable "enable_inspector_lambda_code_scan" {
  description = "Inspector Lambda code scanning. Separately metered from Lambda standard scanning."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Network baseline shape
# ---------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR for the baseline VPC. Private subnets are carved out of it with cidrsubnet()."
  type        = string
  default     = "10.60.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "availability_zone_count" {
  description = "Number of AZs to spread private subnets across. The High baseline raises the effective floor to 3."
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2 && var.availability_zone_count <= 4
    error_message = "availability_zone_count must be between 2 and 4."
  }
}

# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------

variable "tags" {
  description = "Extra tags merged over the baseline tag set on every resource and on the provider default_tags."
  type        = map(string)
  default     = {}
}

variable "data_classification" {
  description = "Value for the DataClassification tag. FedRAMP boundaries are usually tagged so evidence queries can scope by impact level."
  type        = string
  default     = "controlled-unclassified"
}
