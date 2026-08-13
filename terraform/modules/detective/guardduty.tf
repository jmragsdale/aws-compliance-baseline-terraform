# ---------------------------------------------------------------------------
# GuardDuty.
#
# SI-4 (system monitoring) and RA-5 (vulnerability monitoring) again, but
# GuardDuty covers the half Config cannot see: Config knows what a resource
# looks like, GuardDuty knows what it is doing. Cryptomining on an instance, a
# credential used from an anonymising proxy, DNS queries to a known C2 domain --
# none of those are configuration state.
#
# IR-4: GuardDuty findings are the trigger for the incident response process,
# which is why they are routed to the same evidence pipeline as everything else
# rather than living in a console nobody opens.
# ---------------------------------------------------------------------------

locals {
  guardduty_count = var.enable_guardduty ? 1 : 0

  # Each feature is separately metered. Malware protection is the expensive one
  # and gets its own switch; the rest are cheap relative to the detection they
  # provide and are on whenever GuardDuty is.
  guardduty_features = var.enable_guardduty ? merge(
    {
      # SI-4: object-level S3 activity from a compromised principal.
      "S3_DATA_EVENTS" = "ENABLED"
      # AU-2: Kubernetes API audit records, which no other service collects.
      "EKS_AUDIT_LOGS" = "ENABLED"
      # SI-4: anomalous database login patterns.
      "RDS_LOGIN_EVENTS" = "ENABLED"
      # SC-7: outbound network activity from Lambda, the usual blind spot.
      "LAMBDA_NETWORK_LOGS" = "ENABLED"
      # SI-3: process-level detection inside EKS, ECS and EC2.
      "RUNTIME_MONITORING" = "ENABLED"
    },
    var.enable_guardduty_malware_protection ? {
      # SI-3 (malicious code protection): snapshots and scans EBS volumes on a
      # suspicious finding. Charged per GB scanned.
      "EBS_MALWARE_PROTECTION" = "ENABLED"
    } : {},
  ) : {}
}

resource "aws_guardduty_detector" "this" {
  count = local.guardduty_count

  # checkov:skip=CKV2_AWS_3:Organization-wide enablement is handled by aws_guardduty_organization_configuration.this with auto_enable_organization_members = "ALL" and per-feature auto-enable. The graph check expects a single-account shape.
  enable = true

  # SI-4: detection latency comes from the FedRAMP baseline. Fifteen minutes at
  # High is the difference between catching a credential misuse during the
  # session and reading about it afterwards.
  finding_publishing_frequency = var.guardduty_publishing_frequency

  tags = local.tags
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = local.guardduty_features

  detector_id = aws_guardduty_detector.this[0].id
  name        = each.key
  status      = each.value
}

# AC-5: administered from the security tooling account, same reasoning as
# Security Hub.
resource "aws_guardduty_organization_admin_account" "this" {
  count = var.enable_guardduty && var.is_organization ? 1 : 0

  admin_account_id = var.security_tooling_account_id
}

# CM-2: every account that joins the organization gets a detector without a
# human step. AUTO_ENABLE on new accounts only would leave existing accounts
# behind, so ALL is used.
resource "aws_guardduty_organization_configuration" "this" {
  count = var.enable_guardduty && var.is_organization ? 1 : 0

  auto_enable_organization_members = "ALL"
  detector_id                      = aws_guardduty_detector.this[0].id

  depends_on = [aws_guardduty_organization_admin_account.this]
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = var.is_organization ? local.guardduty_features : {}

  detector_id = aws_guardduty_detector.this[0].id
  name        = each.key
  auto_enable = "ALL"

  depends_on = [aws_guardduty_organization_configuration.this]
}
