# ---------------------------------------------------------------------------
# VPC endpoints.
#
# SC-7(4) and AC-4: without these, a workload that needs to call KMS or write to
# CloudWatch Logs needs a route to the internet, and once that route exists it
# is available to everything else in the subnet including whatever an attacker
# leaves behind. Endpoints let the private-only VPC above be genuinely
# private-only rather than aspirationally so.
#
# The endpoint policies carry the same organization perimeter as the RCPs, so a
# leaked credential from another organization cannot use our endpoint to reach
# its own buckets -- the "endpoint as an exfiltration path" problem.
# ---------------------------------------------------------------------------

locals {
  endpoint_count = var.enable_vpc_endpoints ? 1 : 0

  # Gateway endpoints are free and route-table based. There is no reason not to
  # have them and one very good reason to: S3 traffic that leaves the VPC is
  # both billable and un-inspectable.
  gateway_endpoints = var.enable_vpc_endpoints ? toset(["s3", "dynamodb"]) : toset([])

  # Interface endpoints cost roughly $7/month per endpoint per AZ, which is why
  # this list is the minimum a compliance baseline needs rather than everything
  # available. kms/logs/monitoring/sts are what the controls in this repo
  # themselves depend on; ssm/ssmmessages/ec2messages are what Session Manager
  # needs, which is how you administer instances without inbound SSH.
  interface_endpoints = var.enable_vpc_endpoints ? toset([
    "kms",
    "logs",
    "monitoring",
    "sts",
    "ssm",
    "ssmmessages",
    "ec2messages",
    "config",
  ]) : toset([])
}

# SC-7: the endpoint security group accepts 443 from inside the VPC only. It is
# deliberately not reusable for anything else.
resource "aws_security_group" "endpoints" {
  count = local.endpoint_count

  name        = "${var.name_prefix}-vpc-endpoints"
  description = "HTTPS from within the baseline VPC to interface endpoints only (SC-7)"
  vpc_id      = aws_vpc.baseline.id

  # checkov:skip=CKV2_AWS_5:Attached to every interface endpoint via aws_vpc_endpoint.interface.security_group_ids. Checkov's graph does not follow the for_each reference.

  tags = merge(local.tags, { Name = "${var.name_prefix}-vpc-endpoints" })
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  count = local.endpoint_count

  security_group_id = aws_security_group.endpoints[0].id
  description       = "HTTPS from the VPC CIDR"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# Egress is scoped back to the VPC CIDR rather than left open. An interface
# endpoint ENI never needs to originate a connection anywhere else, and an
# unrestricted egress rule on a security group attached to something inside the
# data path is exactly what SC-7 is about.
resource "aws_vpc_security_group_egress_rule" "endpoints_https" {
  count = local.endpoint_count

  security_group_id = aws_security_group.endpoints[0].id
  description       = "HTTPS responses back into the VPC CIDR"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

data "aws_iam_policy_document" "endpoint_perimeter" {
  # This document is a *VPC endpoint policy*, not an IAM policy. Endpoint
  # policies are intersected with the caller's IAM permissions and the resource
  # policy -- they can only ever narrow access, never grant it. The broad Allow
  # is what keeps the endpoint usable at all; the narrowing is the Deny below.
  # checkov:skip=CKV_AWS_1:VPC endpoint policy, not an identity policy. It cannot grant privileges; access is the intersection of this, the caller IAM policy and the resource policy.
  # checkov:skip=CKV_AWS_49:Same -- an endpoint policy without a broad Allow blocks every call through the endpoint. The perimeter is established by the aws:ResourceOrgID Deny.
  # checkov:skip=CKV2_AWS_40:Same -- this document is never attached to a principal.
  # Allow the normal case explicitly; an endpoint policy with only a Deny still
  # needs an Allow or nothing works.
  statement {
    sid       = "AllowOrganizationPrincipals"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
  }

  # AC-4: an endpoint is a hole in the perimeter that leads to every account in
  # AWS, not just ours. This is what makes it lead only to ours.
  statement {
    sid       = "DenyNonOrganizationResources"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "aws:ResourceOrgID"
      values   = [var.organization_id]
    }
  }
}

resource "aws_vpc_endpoint" "gateway" {
  for_each = local.gateway_endpoints

  vpc_id            = aws_vpc.baseline.id
  service_name      = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = data.aws_iam_policy_document.endpoint_perimeter.json

  tags = merge(local.tags, { Name = "${var.name_prefix}-${each.key}-gateway" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.baseline.id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  security_group_ids  = [aws_security_group.endpoints[0].id]
  policy              = data.aws_iam_policy_document.endpoint_perimeter.json
  private_dns_enabled = true

  tags = merge(local.tags, { Name = "${var.name_prefix}-${each.key}-interface" })
}
