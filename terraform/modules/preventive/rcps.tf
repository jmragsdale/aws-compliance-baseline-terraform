# ---------------------------------------------------------------------------
# Resource control policies.
#
# SCPs constrain what *our principals* can do. RCPs constrain what *anyone* can
# do to *our resources* -- including principals in accounts we have never heard
# of, whose identity policies we cannot see. That is the missing half of a data
# perimeter, and it is why SC-7 (boundary protection) and AC-4 (information
# flow enforcement) are not satisfied by SCPs alone.
#
# The classic gap RCPs close: a bucket policy that trusts a partner account, a
# role that trusts a wildcard external id, an IAM user's key pasted into a
# third-party SaaS. None of those are visible from the identity side.
#
# RCPs apply to S3, STS, KMS, SQS and Secrets Manager. Resources of other types
# are unaffected, which is worth stating plainly rather than implying the
# perimeter is total.
# ---------------------------------------------------------------------------

locals {
  # AWS service principals legitimately access our resources without an
  # organization id -- log delivery being the obvious one. Excluding them by
  # PrincipalIsAWSService rather than by name avoids an ever-growing allow-list.
  rcp_data_perimeter = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAccessFromOutsideOrganization"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "s3:*",
          "sts:AssumeRole",
          "sts:AssumeRoleWithSAML",
          "sts:AssumeRoleWithWebIdentity",
          "kms:*",
          "secretsmanager:*",
          "sqs:*",
        ]
        Resource = "*"
        Condition = {
          StringNotEqualsIfExists = { "aws:PrincipalOrgID" = var.organization_id }
          BoolIfExists            = { "aws:PrincipalIsAWSService" = "false" }
        }
      },
    ]
  })

  # The confused-deputy shape: an AWS service acting on behalf of a *different*
  # customer's account touching our resource. aws:SourceOrgID is the condition
  # key AWS added specifically for this and it is not set by anything else.
  rcp_confused_deputy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyServiceAccessOnBehalfOfOtherOrganizations"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "s3:*",
          "kms:*",
          "secretsmanager:*",
          "sqs:*",
        ]
        Resource = "*"
        Condition = {
          StringNotEqualsIfExists = { "aws:SourceOrgID" = var.organization_id }
          Bool                    = { "aws:PrincipalIsAWSService" = "true" }
        }
      },
      {
        # SC-8: transport encryption enforced at the perimeter, so a bucket
        # created tomorrow without the usual policy statement is still covered.
        Sid       = "DenyInsecureTransportOrganizationWide"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["s3:*", "sqs:*", "secretsmanager:*"]
        Resource  = "*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })

  rcps = var.is_organization ? {
    perimeter       = { id = aws_organizations_policy.rcp_data_perimeter[0].id }
    confused_deputy = { id = aws_organizations_policy.rcp_confused_deputy[0].id }
  } : {}

  rcp_attachments = var.is_organization ? {
    for pair in setproduct(keys(local.rcps), var.target_ou_ids) :
    "${pair[0]}:${pair[1]}" => { policy = local.rcps[pair[0]].id, target = pair[1] }
  } : {}
}

resource "aws_organizations_policy" "rcp_data_perimeter" {
  count = local.org_count

  name        = "${var.name_prefix}-rcp-data-perimeter"
  description = "Denies access to organization resources by principals outside the organization (SC-7, AC-4)"
  type        = "RESOURCE_CONTROL_POLICY"
  content     = local.rcp_data_perimeter

  tags = local.tags
}

resource "aws_organizations_policy" "rcp_confused_deputy" {
  count = local.org_count

  name        = "${var.name_prefix}-rcp-confused-deputy"
  description = "Denies AWS service access on behalf of other organizations and denies plaintext transport (SC-7, SC-8)"
  type        = "RESOURCE_CONTROL_POLICY"
  content     = local.rcp_confused_deputy

  tags = local.tags
}

resource "aws_organizations_policy_attachment" "rcp" {
  for_each = local.rcp_attachments

  policy_id = each.value.policy
  target_id = each.value.target
}
