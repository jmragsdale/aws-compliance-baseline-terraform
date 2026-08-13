terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Organization-wide FedRAMP High posture.
#
# This is the expensive, complete shape: every preventive guardrail attached at
# the organization root, every detective service on, audit records replicated
# across two regions, and the evidence lake streaming findings for the life of
# the ATO.
#
# Run this from the Organizations management account, or from a delegated
# administrator with the Organizations, CloudTrail and Config delegations
# already in place. It will not work from a member account and it is not
# supposed to.
#
# Account IDs below are placeholders. Replace them; do not commit real ones.
# ---------------------------------------------------------------------------

module "compliance_baseline" {
  source = "../../terraform"

  # High rather than Moderate, which turns on: 7-year Object Lock, quarterly key
  # rotation, cross-region replication of the archive, aws:kms-only S3 PUTs,
  # 1-hour session ceiling, 20-character passwords, 3 AZs, 60-second flow log
  # aggregation and the FedRAMP High conformance pack.
  fedramp_baseline = "high"
  deployment_scope = "organization"

  name_prefix    = "fedramp-high"
  primary_region = "us-east-1"
  replica_region = "us-west-2"

  # Placeholders. AWS GovCloud partitions use different IDs entirely.
  management_account_id       = "111111111111"
  log_archive_account_id      = "222222222222"
  security_tooling_account_id = "333333333333"
  organization_id             = "o-exampleorgid"

  # Attaching at the root is what makes these guardrails unavoidable. Attaching
  # to a sandbox OU first is the safe rollout; this example shows the end state.
  target_ou_ids = ["r-exam"]

  # The assessment boundary. Anything outside this list is denied outright,
  # which is also how you stop a workload appearing in a region where GuardDuty
  # and Config were never enabled.
  allowed_regions = ["us-east-1", "us-west-2"]

  security_contact_email = "security-alerts@example.gov"

  # --- Preventive ---------------------------------------------------------
  enable_preventive_guardrails = true

  # --- Foundational -------------------------------------------------------
  enable_customer_managed_keys = true
  enable_central_logging       = true

  # Object-level S3 and Lambda invoke events. Materially expensive on a busy
  # organization and required by the High baseline's AU-2 interpretation.
  enable_cloudtrail_data_events = true

  # --- Detective ----------------------------------------------------------
  enable_config            = true
  enable_conformance_packs = true
  enable_security_hub      = true
  enable_guardduty         = true
  enable_access_analyzer   = true

  # EBS snapshot scanning. The single most expensive line item in this file;
  # left on here because SI-3 at High is hard to argue without it.
  enable_guardduty_malware_protection = true

  # Sensitive data discovery and vulnerability scanning.
  enable_macie                      = true
  enable_inspector                  = true
  enable_inspector_lambda_code_scan = true

  # --- Network ------------------------------------------------------------
  enable_network_baseline = true
  enable_vpc_endpoints    = true
  vpc_cidr                = "10.60.0.0/16"
  availability_zone_count = 3

  # --- Evidence -----------------------------------------------------------
  enable_evidence_lake = true

  tags = {
    Owner       = "platform-security"
    CostCenter  = "CC-1042"
    Environment = "production"
    SSPBoundary = "core-authorization-boundary"
  }
}

output "baseline" {
  description = "Effective baseline parameters -- attach to the SSP as evidence of what was deployed."
  value       = module.compliance_baseline.baseline
}

output "enabled_controls" {
  description = "Which control planes this deployment turned on."
  value       = module.compliance_baseline.enabled_controls
}

output "evidence_query_target" {
  description = "Athena workgroup, database and table for auditor queries."
  value       = module.compliance_baseline.evidence_query_target
}
