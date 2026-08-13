# ---------------------------------------------------------------------------
# IAM Access Analyzer.
#
# Two analyzers because they answer two different questions, and the second one
# is the one nobody runs.
#
# External access (CIS 1.20, AC-3, AC-21): which of our resources can be
# reached from outside the organization? This is provable rather than
# heuristic -- Access Analyzer uses automated reasoning over the resource
# policies, so a "no external access" result is a proof, not a scan.
#
# Unused access (AC-6, AC-6(7)): which roles, users, permissions and access
# keys have not been used? Least privilege is not a state you reach, it is a
# thing that decays; this is the only AWS service that measures the decay.
# ---------------------------------------------------------------------------

locals {
  analyzer_type_external = var.is_organization ? "ORGANIZATION" : "ACCOUNT"
  analyzer_type_unused   = var.is_organization ? "ORGANIZATION_UNUSED_ACCESS" : "ACCOUNT_UNUSED_ACCESS"
}

resource "aws_accessanalyzer_analyzer" "external" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = "${var.name_prefix}-external-access"
  type          = local.analyzer_type_external

  tags = local.tags
}

resource "aws_accessanalyzer_analyzer" "unused" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = "${var.name_prefix}-unused-access"
  type          = local.analyzer_type_unused

  configuration {
    unused_access {
      # AC-6(7) requires a defined review frequency. The baseline sets it: 90
      # days at Moderate, 45 at High.
      unused_access_age = var.unused_access_age_days
    }
  }

  tags = local.tags
}
