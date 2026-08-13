# ---------------------------------------------------------------------------
# Baseline VPC.
#
# SC-7 (boundary protection) is the control, and the design decision behind it
# is that this VPC has no internet gateway at all. Not "an internet gateway with
# a restrictive route table" -- none. Egress that does not exist cannot be
# misconfigured, and the VPC endpoints below give workloads the AWS APIs they
# actually need without one.
#
# AU-2 for the network layer comes from flow logs delivered to the same archive
# as the API audit records, so a single Athena query can correlate "who called
# the API" with "what talked to what".
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_region" "current" {}

locals {
  tags = merge(var.tags, { Module = "network" })

  region = data.aws_region.current.region

  azs = slice(data.aws_availability_zones.available.names, 0, var.availability_zone_count)

  private_subnets = {
    for idx, az in local.azs : az => {
      cidr = cidrsubnet(var.vpc_cidr, 4, idx)
      az   = az
    }
  }
}

resource "aws_vpc" "baseline" {
  cidr_block = var.vpc_cidr

  # SC-7 and AU-2: DNS hostnames are required for interface endpoints to resolve
  # privately, and private DNS is what stops a workload silently falling back to
  # the public endpoint.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.tags, { Name = "${var.name_prefix}-baseline" })
}

# CIS 5.4 / SC-7: AWS creates a default security group allowing all traffic
# between its members. It cannot be deleted, so the only remedy is to adopt it
# and empty it. An unmanaged default SG is the most common way a "locked down"
# VPC turns out to be flat internally.
resource "aws_default_security_group" "baseline" {
  vpc_id = aws_vpc.baseline.id

  # No ingress and no egress blocks: absence here means the rules are removed.

  tags = merge(local.tags, { Name = "${var.name_prefix}-default-DO-NOT-USE" })
}

# SC-7: the default NACL is likewise adopted and reduced. It is left permissive
# within the VPC CIDR only -- NACLs are stateless, so denying return traffic
# here breaks everything in a way that is hard to diagnose.
resource "aws_default_network_acl" "baseline" {
  default_network_acl_id = aws_vpc.baseline.default_network_acl_id

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-default-nacl" })

  lifecycle {
    # Subnet associations are managed by the subnets themselves; without this
    # every apply fights the ones Terraform did not create.
    ignore_changes = [subnet_ids]
  }
}

resource "aws_subnet" "private" {
  for_each = local.private_subnets

  vpc_id            = aws_vpc.baseline.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  # SC-7: no public addressing anywhere in this VPC, so an instance launched
  # without an explicit setting cannot become internet-reachable by accident.
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-private-${each.key}"
    Tier = "private"
  })
}

# One route table with no default route. The only entries it ever gets are the
# implicit local route and the S3/DynamoDB gateway endpoint prefix lists.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.baseline.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-private" })
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

# AU-2 / AU-12: every accepted and rejected flow, delivered to the archive that
# already carries Object Lock and the retention window. Rejects alone would be
# cheaper and would also make lateral movement inside the VPC invisible.
resource "aws_flow_log" "vpc" {
  vpc_id       = aws_vpc.baseline.id
  traffic_type = "ALL"

  log_destination_type = "s3"
  log_destination      = "${var.log_archive_bucket_arn}/vpc-flow-logs/"

  # Baseline-driven: one-minute aggregation at High shortens the window in which
  # a short-lived exfiltration connection is invisible.
  max_aggregation_interval = var.flow_log_aggregation_seconds

  destination_options {
    # Parquet with hourly partitions so the Athena queries in
    # scripts/export-evidence.sh scan megabytes rather than terabytes.
    file_format                = "parquet"
    per_hour_partition         = true
    hive_compatible_partitions = true
  }

  # AU-3: the default format omits the fields that make a flow attributable --
  # which account, which interface, which subnet, and whether the flow was
  # observed by the VPC or by a transit gateway.
  log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}", "$${srcaddr}",
    "$${dstaddr}", "$${srcport}", "$${dstport}", "$${protocol}", "$${packets}",
    "$${bytes}", "$${start}", "$${end}", "$${action}", "$${log-status}",
    "$${vpc-id}", "$${subnet-id}", "$${instance-id}", "$${tcp-flags}",
    "$${type}", "$${pkt-srcaddr}", "$${pkt-dstaddr}", "$${region}", "$${az-id}",
    "$${flow-direction}", "$${traffic-path}",
  ])

  tags = merge(local.tags, { Name = "${var.name_prefix}-vpc-flow-logs" })
}
