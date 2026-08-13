package terraform.encryption

import rego.v1

# --- helpers ---------------------------------------------------------------

plan(resources) := {"resource_changes": resources}

kms_key(name, after) := {
	"address": name,
	"type": "aws_kms_key",
	"change": {"actions": ["create"], "after": after},
}

trail(name, after) := {
	"address": name,
	"type": "aws_cloudtrail",
	"change": {"actions": ["create"], "after": after},
}

pab(name, after) := {
	"address": name,
	"type": "aws_s3_bucket_public_access_block",
	"change": {"actions": ["create"], "after": after},
}

all_flags_on := {
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

# --- KMS rotation ----------------------------------------------------------

test_kms_rotation_enabled_passes if {
	count(deny) == 0 with input as plan([kms_key(
		"aws_kms_key.logs",
		{"enable_key_rotation": true, "rotation_period_in_days": 90},
	)])
}

test_kms_rotation_disabled_denied if {
	count(deny) == 1 with input as plan([kms_key(
		"aws_kms_key.logs",
		{"enable_key_rotation": false, "rotation_period_in_days": 90},
	)])
}

test_kms_rotation_period_too_long_denied if {
	count(deny) == 1 with input as plan([kms_key(
		"aws_kms_key.logs",
		{"enable_key_rotation": true, "rotation_period_in_days": 730},
	)])
}

test_kms_key_being_destroyed_is_ignored if {
	count(deny) == 0 with input as plan([{
		"address": "aws_kms_key.old",
		"type": "aws_kms_key",
		"change": {"actions": ["delete"], "after": null},
	}])
}

# --- CloudTrail ------------------------------------------------------------

test_compliant_trail_passes if {
	count(deny) == 0 with input as plan([trail(
		"aws_cloudtrail.org",
		{"enable_log_file_validation": true, "is_multi_region_trail": true},
	)])
}

test_trail_without_log_file_validation_denied if {
	count(deny) == 1 with input as plan([trail(
		"aws_cloudtrail.org",
		{"enable_log_file_validation": false, "is_multi_region_trail": true},
	)])
}

test_regional_only_trail_denied if {
	count(deny) == 1 with input as plan([trail(
		"aws_cloudtrail.org",
		{"enable_log_file_validation": true, "is_multi_region_trail": false},
	)])
}

# --- Block Public Access ---------------------------------------------------

test_all_four_bpa_flags_passes if {
	count(deny) == 0 with input as plan([pab("aws_s3_bucket_public_access_block.archive", all_flags_on)])
}

test_three_of_four_bpa_flags_denied if {
	count(deny) == 1 with input as plan([pab(
		"aws_s3_bucket_public_access_block.archive",
		json.patch(all_flags_on, [{"op": "replace", "path": "/restrict_public_buckets", "value": false}]),
	)])
}

test_account_level_bpa_checked_too if {
	count(deny) == 1 with input as plan([{
		"address": "aws_s3_account_public_access_block.this",
		"type": "aws_s3_account_public_access_block",
		"change": {
			"actions": ["create"],
			"after": json.patch(all_flags_on, [{"op": "replace", "path": "/ignore_public_acls", "value": false}]),
		},
	}])
}

# --- SSE algorithm ---------------------------------------------------------

test_kms_sse_algorithm_passes if {
	count(deny) == 0 with input as plan([{
		"address": "aws_s3_bucket_server_side_encryption_configuration.archive",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
		},
	}])
}

test_unknown_sse_algorithm_denied if {
	count(deny) == 1 with input as plan([{
		"address": "aws_s3_bucket_server_side_encryption_configuration.archive",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "none"}]}]},
		},
	}])
}
