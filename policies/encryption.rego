# Encryption invariants checked against `terraform show -json <plan>`.
#
# These are the assertions Checkov and Trivy do not make, because they are
# specific to this baseline rather than generic best practice: a customer-managed
# key whose rotation period exceeds the FedRAMP cryptoperiod, a trail without log
# file validation, or a Block Public Access resource with one of the four flags
# left off are all valid Terraform and all break a control this repo claims.
#
# Run:  conftest test --policy policies plan.json
# Test: conftest verify --policy policies
package terraform.encryption

import rego.v1

# Resources being destroyed cannot violate anything.
planned_resources(resource_type) := [r |
	some r in input.resource_changes
	r.type == resource_type
	not is_delete(r)
]

is_delete(r) if {
	count(r.change.actions) == 1
	r.change.actions[0] == "delete"
}

# SC-12(1): every customer-managed key rotates, and the cryptoperiod never
# exceeds one year. FedRAMP High tightens this to 90 days via the baseline map.
deny contains msg if {
	some key in planned_resources("aws_kms_key")
	key.change.after.enable_key_rotation != true
	msg := sprintf("SC-12(1): KMS key %q has automatic rotation disabled", [key.address])
}

deny contains msg if {
	some key in planned_resources("aws_kms_key")
	key.change.after.enable_key_rotation == true
	key.change.after.rotation_period_in_days > 365
	msg := sprintf(
		"SC-12(1): KMS key %q rotates every %d days, which exceeds the one-year FedRAMP cryptoperiod",
		[key.address, key.change.after.rotation_period_in_days],
	)
}

# AU-9(3) and CIS 3.1/3.2: a trail without log file validation produces logs
# nobody can prove are unaltered, and a regional trail leaves regions unaudited.
deny contains msg if {
	some trail in planned_resources("aws_cloudtrail")
	trail.change.after.enable_log_file_validation != true
	msg := sprintf("AU-9(3): CloudTrail %q has log file validation disabled", [trail.address])
}

deny contains msg if {
	some trail in planned_resources("aws_cloudtrail")
	trail.change.after.is_multi_region_trail != true
	msg := sprintf("CIS 3.1: CloudTrail %q is not a multi-region trail", [trail.address])
}

# AC-3 / CIS 2.1.4: all four Block Public Access flags, or none of them count.
# Three-of-four is the configuration people ship and then get surprised by.
bpa_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

deny contains msg if {
	some pab in planned_resources("aws_s3_bucket_public_access_block")
	some flag in bpa_flags
	pab.change.after[flag] != true
	msg := sprintf("AC-3: %q leaves %s disabled; all four Block Public Access flags are required", [pab.address, flag])
}

deny contains msg if {
	some pab in planned_resources("aws_s3_account_public_access_block")
	some flag in bpa_flags
	pab.change.after[flag] != true
	msg := sprintf("CIS 2.1.4: account-level %q leaves %s disabled", [pab.address, flag])
}

# SC-28: SSE-S3 and aws:kms are the only acceptable algorithms. An SSE config
# that names anything else is a typo that silently disables encryption.
valid_sse_algorithms := {"aws:kms", "AES256"}

deny contains msg if {
	some sse in planned_resources("aws_s3_bucket_server_side_encryption_configuration")
	some sse_rule in sse.change.after.rule
	some sse_default in sse_rule.apply_server_side_encryption_by_default
	not valid_sse_algorithms[sse_default.sse_algorithm]
	msg := sprintf("SC-28: %q uses unsupported sse_algorithm %q", [sse.address, sse_default.sse_algorithm])
}
