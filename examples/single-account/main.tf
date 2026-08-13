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
# Single-account FedRAMP Moderate posture.
#
# A deliberately different shape from examples/org-wide, not a smaller copy of
# it. This is what you deploy into one account that is not the management
# account of an organization -- a lab, a proof of concept, or a workload
# account whose organization is managed by someone else.
#
# Everything organization-owned is gated off by deployment_scope. No SCPs, no
# RCPs, no organization trail, no delegated administrators, no Config
# aggregator, and the analyzers switch from ORGANIZATION to ACCOUNT type. What
# remains is genuinely useful and genuinely cheaper.
#
# The honest limitation: without SCPs, nothing here is *preventive* except the
# account-level settings. A sufficiently privileged principal in this account
# can undo any of it. In organization mode they cannot. That difference is the
# entire argument for owning the organization.
# ---------------------------------------------------------------------------

module "compliance_baseline" {
  source = "../../terraform"

  fedramp_baseline = "moderate"
  deployment_scope = "single_account"

  name_prefix    = "cb-lab"
  primary_region = "us-east-1"
  replica_region = "us-west-2"

  management_account_id       = "111111111111"
  log_archive_account_id      = "111111111111"
  security_tooling_account_id = "111111111111"
  organization_id             = "o-exampleorgid"

  # No OU targets: with deployment_scope = "single_account" the policy resources
  # are not created at all, so this list is unused. Left empty on purpose.
  target_ou_ids = []

  allowed_regions = ["us-east-1"]

  # The account-level hardening (S3 Block Public Access, EBS encryption by
  # default, password policy) still applies -- those are account-scoped
  # resources, not Organizations policies.
  enable_preventive_guardrails = true

  # Foundational. CMKs on, because the CIS check for a CMK-encrypted trail is
  # one of the cheapest wins available and the key cost is $3/month for three.
  enable_customer_managed_keys = true
  enable_central_logging       = true

  # Off: on a lab account, object-level events are the single easiest way to
  # produce a surprising CloudTrail bill.
  enable_cloudtrail_data_events = false

  # Detective, trimmed to what a single account can justify.
  enable_config            = true
  enable_conformance_packs = true
  enable_security_hub      = true
  enable_guardduty         = true
  enable_access_analyzer   = true

  # Off: metered heavily, and a lab account has nothing worth classifying.
  enable_guardduty_malware_protection = false
  enable_macie                        = false
  enable_inspector                    = false

  # Off: the network baseline is the one module with no compliance value in an
  # account that runs no workloads. Switch it on when there is something to put
  # in the VPC.
  enable_network_baseline = false
  enable_vpc_endpoints    = false

  # Off: without an organization there is no fleet of accounts to aggregate
  # findings from, and Security Hub's own 90-day window is adequate for a lab.
  enable_evidence_lake = false

  tags = {
    Owner       = "platform-security"
    Environment = "lab"
    Ephemeral   = "true"
  }
}

output "baseline" {
  description = "Effective baseline parameters."
  value       = module.compliance_baseline.baseline
}

output "enabled_controls" {
  description = "Which control planes this deployment turned on."
  value       = module.compliance_baseline.enabled_controls
}

output "security_alarms_topic_arn" {
  description = "Subscribe something to this or the CIS alarms fire into the void."
  value       = module.compliance_baseline.security_alarms_topic_arn
}
