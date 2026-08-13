# ---------------------------------------------------------------------------
# Security Hub.
#
# CA-7 (continuous monitoring) and RA-5 (vulnerability monitoring) are the
# controls this satisfies, but the practical value is narrower and worth being
# precise about: Security Hub is a *finding aggregator plus a checklist runner*.
# It evaluates the CIS, NIST 800-53 Rev 5 and FSBP rule sets against the
# configuration Config records, and it normalises GuardDuty / Inspector / Macie
# findings into one schema (ASFF) so the evidence pipeline has one shape to
# parse instead of four.
#
# It does not make anything compliant. It tells you, continuously, which of a
# published checklist you currently fail -- which is exactly what an assessor
# asks for and exactly what nobody has when they are asked.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  tags = merge(var.tags, { Module = "detective" })

  securityhub_count = var.enable_security_hub ? 1 : 0
  config_count      = var.enable_config ? 1 : 0

  # Standards ARNs are region-scoped but account-less. Pinning the version is
  # deliberate: AWS publishes a new CIS version without deprecating the old one,
  # and an unpinned subscription silently changes which checks you are measured
  # against between applies.
  standards_arns = {
    cis_v5 = "arn:${local.partition}:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/5.0.0"
    nist   = "arn:${local.partition}:securityhub:${local.region}::standards/nist-800-53/v/5.0.0"
    fsbp   = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  }
}

resource "aws_securityhub_account" "this" {
  count = local.securityhub_count

  # CA-7: control findings are generated per standard rather than collapsed to
  # one finding per resource, so a resource failing three standards produces
  # three pieces of evidence rather than one ambiguous one.
  control_finding_generator = "STANDARD_CONTROL"

  # New controls added to a subscribed standard are enabled automatically.
  # Turning this off means the baseline silently stops covering new AWS
  # services as they ship.
  auto_enable_controls = true

  enable_default_standards = false
}

# AC-5: Security Hub is administered from the security tooling account, not the
# management account. The management account has the power to change the
# organization; the account that watches for changes should not be it.
resource "aws_securityhub_organization_admin_account" "this" {
  count = var.enable_security_hub && var.is_organization ? 1 : 0

  admin_account_id = var.security_tooling_account_id

  depends_on = [aws_securityhub_account.this]
}

# CM-2 / CA-7: an account created next month is monitored from the moment it
# joins, with no onboarding step for anyone to forget.
#
# Note the counter-intuitive attribute values. Under *central* configuration the
# legacy auto_enable flags must be off: enablement is expressed by a
# configuration policy associated with an OU (below) rather than by a global
# toggle. Setting auto_enable = true alongside configuration_type = "CENTRAL"
# is rejected by the API, which is the kind of thing that only shows up at
# apply time.
resource "aws_securityhub_organization_configuration" "this" {
  count = var.enable_security_hub && var.is_organization ? 1 : 0

  auto_enable           = false
  auto_enable_standards = "NONE"

  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [
    aws_securityhub_organization_admin_account.this,
    aws_securityhub_finding_aggregator.this,
  ]
}

# CM-2 / CM-6: the configuration policy is the thing that actually enables
# Security Hub and the three standards across the organization. Expressing it as
# a policy rather than a per-account setting means an account that joins an
# associated OU inherits the full standard set immediately, and drift in a
# member account is corrected rather than merely reported.
resource "aws_securityhub_configuration_policy" "baseline" {
  count = var.enable_security_hub && var.is_organization ? 1 : 0

  name        = "${var.name_prefix}-baseline"
  description = "Security Hub enabled with CIS v5.0, NIST 800-53 Rev 5 and FSBP for every associated account (CA-7)"

  configuration_policy {
    service_enabled       = true
    enabled_standard_arns = values(local.standards_arns)

    security_controls_configuration {
      # Empty means "every control in the enabled standards stays enabled".
      # Any control disabled here needs a documented risk acceptance in the
      # POA&M, which is why the list is empty rather than pre-trimmed.
      disabled_control_identifiers = []
    }
  }

  depends_on = [aws_securityhub_organization_configuration.this]
}

resource "aws_securityhub_configuration_policy_association" "targets" {
  for_each = var.enable_security_hub && var.is_organization ? toset(var.target_ou_ids) : toset([])

  target_id = each.value
  policy_id = aws_securityhub_configuration_policy.baseline[0].id
}

# SI-4: findings from every enabled region are pulled into the home region so
# the evidence pipeline has one place to read and an assessor has one console.
resource "aws_securityhub_finding_aggregator" "this" {
  count = local.securityhub_count

  linking_mode      = "SPECIFIED_REGIONS"
  specified_regions = var.aggregator_regions

  depends_on = [aws_securityhub_account.this]
}

# CIS AWS Foundations Benchmark v5.0. The benchmark this repo is written against.
resource "aws_securityhub_standards_subscription" "cis" {
  count = local.securityhub_count

  standards_arn = local.standards_arns.cis_v5

  depends_on = [aws_securityhub_account.this]
}

# NIST SP 800-53 Rev 5. Roughly 240 automated checks mapped to control
# identifiers, which is what makes a Security Hub export usable as evidence
# against a FedRAMP control set rather than just a security score.
resource "aws_securityhub_standards_subscription" "nist" {
  count = local.securityhub_count

  standards_arn = local.standards_arns.nist

  depends_on = [aws_securityhub_account.this]
}

# AWS Foundational Security Best Practices. Not a compliance framework, but it
# covers service-specific misconfigurations the other two do not reach.
resource "aws_securityhub_standards_subscription" "fsbp" {
  count = local.securityhub_count

  standards_arn = local.standards_arns.fsbp

  depends_on = [aws_securityhub_account.this]
}
