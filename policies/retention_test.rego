package terraform.retention

import rego.v1

plan(resources) := {"resource_changes": resources}

log_group(name, after) := {
	"address": name,
	"type": "aws_cloudwatch_log_group",
	"change": {"actions": ["create"], "after": after},
}

object_lock(name, mode, days) := {
	"address": name,
	"type": "aws_s3_bucket_object_lock_configuration",
	"change": {
		"actions": ["create"],
		"after": {"rule": [{"default_retention": [{"mode": mode, "days": days}]}]},
	},
}

# --- CloudWatch retention --------------------------------------------------

test_year_retention_passes if {
	count(deny) == 0 with input as plan([log_group(
		"aws_cloudwatch_log_group.cloudtrail",
		{"name": "/aws/cloudtrail/baseline", "retention_in_days": 365},
	)])
}

test_high_baseline_retention_passes if {
	count(deny) == 0 with input as plan([log_group(
		"aws_cloudwatch_log_group.cloudtrail",
		{"name": "/aws/cloudtrail/baseline", "retention_in_days": 1827},
	)])
}

test_short_retention_denied if {
	count(deny) == 1 with input as plan([log_group(
		"aws_cloudwatch_log_group.cloudtrail",
		{"name": "/aws/cloudtrail/baseline", "retention_in_days": 30},
	)])
}

test_never_expire_denied if {
	count(deny) == 1 with input as plan([log_group(
		"aws_cloudwatch_log_group.cloudtrail",
		{"name": "/aws/cloudtrail/baseline", "retention_in_days": 0},
	)])
}

test_firehose_diagnostics_group_exempt if {
	count(deny) == 0 with input as plan([log_group(
		"aws_cloudwatch_log_group.firehose",
		{"name": "/aws/kinesisfirehose/baseline-findings", "retention_in_days": 90},
	)])
}

# --- Object Lock -----------------------------------------------------------

test_compliance_mode_passes if {
	count(deny) == 0 with input as plan([object_lock("aws_s3_bucket_object_lock_configuration.archive", "COMPLIANCE", 2555)])
}

test_governance_mode_denied if {
	count(deny) == 1 with input as plan([object_lock("aws_s3_bucket_object_lock_configuration.archive", "GOVERNANCE", 2555)])
}

test_short_object_lock_denied if {
	count(deny) == 1 with input as plan([object_lock("aws_s3_bucket_object_lock_configuration.archive", "COMPLIANCE", 90)])
}

test_governance_and_short_window_both_denied if {
	count(deny) == 2 with input as plan([object_lock("aws_s3_bucket_object_lock_configuration.archive", "GOVERNANCE", 30)])
}

# --- Versioning ------------------------------------------------------------

test_versioning_enabled_passes if {
	count(deny) == 0 with input as plan([{
		"address": "aws_s3_bucket_versioning.archive",
		"type": "aws_s3_bucket_versioning",
		"change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Enabled"}]}},
	}])
}

test_versioning_suspended_denied if {
	count(deny) == 1 with input as plan([{
		"address": "aws_s3_bucket_versioning.archive",
		"type": "aws_s3_bucket_versioning",
		"change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Suspended"}]}},
	}])
}

# --- Alarm actions ---------------------------------------------------------

test_alarm_with_action_passes if {
	count(deny) == 0 with input as plan([{
		"address": "aws_cloudwatch_metric_alarm.root_usage",
		"type": "aws_cloudwatch_metric_alarm",
		"change": {"actions": ["create"], "after": {"alarm_actions": ["arn:aws:sns:us-east-1:111111111111:alarms"]}},
	}])
}

test_alarm_without_action_denied if {
	count(deny) == 1 with input as plan([{
		"address": "aws_cloudwatch_metric_alarm.root_usage",
		"type": "aws_cloudwatch_metric_alarm",
		"change": {"actions": ["create"], "after": {"alarm_actions": []}},
	}])
}
