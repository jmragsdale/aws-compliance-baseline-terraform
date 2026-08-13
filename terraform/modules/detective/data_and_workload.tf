# ---------------------------------------------------------------------------
# Macie and Inspector.
#
# Both are off by default and both are genuinely expensive, which is why they
# are separate switches rather than part of the detective baseline.
#
# Macie -- RA-2 (security categorization) and MP-4 (media protection). FedRAMP
# expects you to know where controlled unclassified information actually lives,
# not where the data flow diagram says it lives. Macie is the only service that
# answers that for S3 without writing a classifier.
#
# Inspector -- RA-5 (vulnerability monitoring and scanning) and SI-2 (flaw
# remediation). Continuous CVE scanning of EC2, ECR images and Lambda packages,
# with findings normalised into Security Hub alongside everything else.
# ---------------------------------------------------------------------------

resource "aws_macie2_account" "this" {
  count = var.enable_macie ? 1 : 0

  status = "ENABLED"

  # RA-2: hourly is the finest granularity Macie publishes. At this frequency
  # a newly-exposed sensitive bucket is a finding within the hour rather than
  # the day.
  finding_publishing_frequency = "ONE_HOUR"
}

resource "aws_macie2_organization_admin_account" "this" {
  count = var.enable_macie && var.is_organization ? 1 : 0

  admin_account_id = var.security_tooling_account_id

  depends_on = [aws_macie2_account.this]
}

locals {
  # EC2 and ECR are always in scope when Inspector is on. Lambda code scanning
  # is metered separately because it decompiles and analyses the package rather
  # than just reading its dependency manifest.
  inspector_resource_types = var.enable_inspector ? compact([
    "EC2",
    "ECR",
    "LAMBDA",
    var.enable_inspector_lambda_code_scan ? "LAMBDA_CODE" : "",
  ]) : []
}

resource "aws_inspector2_enabler" "this" {
  count = var.enable_inspector ? 1 : 0

  account_ids    = [local.account_id]
  resource_types = local.inspector_resource_types
}

resource "aws_inspector2_delegated_admin_account" "this" {
  count = var.enable_inspector && var.is_organization ? 1 : 0

  account_id = var.security_tooling_account_id
}

# CM-2: scanning covers accounts that join later, without an onboarding step.
resource "aws_inspector2_organization_configuration" "this" {
  count = var.enable_inspector && var.is_organization ? 1 : 0

  auto_enable {
    ec2         = true
    ecr         = true
    lambda      = true
    lambda_code = var.enable_inspector_lambda_code_scan
  }

  depends_on = [aws_inspector2_delegated_admin_account.this]
}
