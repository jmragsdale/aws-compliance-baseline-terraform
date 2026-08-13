package terraform.data_perimeter

import rego.v1

plan(resources) := {"resource_changes": resources}

bucket_policy(name, statements) := {
	"address": name,
	"type": "aws_s3_bucket_policy",
	"change": {
		"actions": ["create"],
		"after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": statements})},
	},
}

tls_deny := {
	"Sid": "DenyInsecureTransport",
	"Effect": "Deny",
	"Principal": {"AWS": "*"},
	"Action": "s3:*",
	"Resource": "*",
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}

org_scoped_allow := {
	"Sid": "AllowOrgRead",
	"Effect": "Allow",
	"Principal": {"AWS": "*"},
	"Action": "s3:GetObject",
	"Resource": "*",
	"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}},
}

open_allow := {
	"Sid": "AllowEveryone",
	"Effect": "Allow",
	"Principal": {"AWS": "*"},
	"Action": "s3:GetObject",
	"Resource": "*",
}

ip_scoped_allow := {
	"Sid": "AllowFromOffice",
	"Effect": "Allow",
	"Principal": {"AWS": "*"},
	"Action": "s3:GetObject",
	"Resource": "*",
	"Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
}

# --- wildcard principals ---------------------------------------------------

test_org_scoped_allow_passes if {
	count(deny) == 0 with input as plan([bucket_policy("aws_s3_bucket_policy.archive", [tls_deny, org_scoped_allow])])
}

test_unconditional_wildcard_principal_denied if {
	count(deny) == 1 with input as plan([bucket_policy("aws_s3_bucket_policy.archive", [tls_deny, open_allow])])
}

# The case generic scanners miss: a condition exists, but it constrains network
# location rather than identity, so the perimeter is not actually established.
test_ip_only_condition_is_not_a_perimeter if {
	count(deny) == 1 with input as plan([bucket_policy("aws_s3_bucket_policy.archive", [tls_deny, ip_scoped_allow])])
}

test_service_principal_allow_passes if {
	count(deny) == 0 with input as plan([bucket_policy("aws_s3_bucket_policy.archive", [
		tls_deny,
		{
			"Sid": "CloudTrailWrite",
			"Effect": "Allow",
			"Principal": {"Service": "cloudtrail.amazonaws.com"},
			"Action": "s3:PutObject",
			"Resource": "*",
		},
	])])
}

# --- TLS enforcement -------------------------------------------------------

test_bucket_policy_without_tls_deny_is_denied if {
	count(deny) == 1 with input as plan([bucket_policy("aws_s3_bucket_policy.archive", [org_scoped_allow])])
}

# --- security group rules --------------------------------------------------

test_scoped_ingress_passes if {
	count(deny) == 0 with input as plan([{
		"address": "aws_vpc_security_group_ingress_rule.endpoints_https",
		"type": "aws_vpc_security_group_ingress_rule",
		"change": {"actions": ["create"], "after": {"cidr_ipv4": "10.60.0.0/16", "from_port": 443}},
	}])
}

test_open_ipv4_ingress_denied if {
	count(deny) == 1 with input as plan([{
		"address": "aws_vpc_security_group_ingress_rule.bad",
		"type": "aws_vpc_security_group_ingress_rule",
		"change": {"actions": ["create"], "after": {"cidr_ipv4": "0.0.0.0/0", "from_port": 22}},
	}])
}

test_open_ipv6_ingress_denied if {
	count(deny) == 1 with input as plan([{
		"address": "aws_vpc_security_group_ingress_rule.bad6",
		"type": "aws_vpc_security_group_ingress_rule",
		"change": {"actions": ["create"], "after": {"cidr_ipv6": "::/0", "from_port": 22}},
	}])
}

# --- VPC endpoint policies -------------------------------------------------

test_endpoint_with_policy_passes if {
	count(deny) == 0 with input as plan([{
		"address": "aws_vpc_endpoint.interface[\"kms\"]",
		"type": "aws_vpc_endpoint",
		"change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}},
	}])
}

test_endpoint_without_policy_denied if {
	count(deny) == 1 with input as plan([{
		"address": "aws_vpc_endpoint.interface[\"kms\"]",
		"type": "aws_vpc_endpoint",
		"change": {"actions": ["create"], "after": {"policy": ""}},
	}])
}
