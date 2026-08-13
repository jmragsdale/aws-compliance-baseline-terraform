# Audit record retention invariants.
#
# AU-11 is the control everyone claims and nobody checks, because the failure is
# invisible: a log group with 30-day retention looks identical in the console to
# one with 365-day retention until an assessor asks for records from eight
# months ago. These rules make that failure a build failure.
#
# The thresholds are the FedRAMP Moderate floor. High is stricter, and a
# deployment at High that only meets these numbers is still non-compliant --
# but it is not silently broken, which is what this file is for.
package terraform.retention

import rego.v1

moderate_minimum_days := 365

planned_resources(resource_type) := [r |
	some r in input.resource_changes
	r.type == resource_type
	not is_delete(r)
]

is_delete(r) if {
	count(r.change.actions) == 1
	r.change.actions[0] == "delete"
}

# AU-11: no audit log group may retain for less than a year, and "never expire"
# (retention_in_days == 0) is not acceptable either -- unbounded retention is an
# unbounded bill and an unbounded discovery surface.
deny contains msg if {
	some group in planned_resources("aws_cloudwatch_log_group")
	group.change.after.retention_in_days < moderate_minimum_days
	group.change.after.retention_in_days != 0
	not is_operational_log_group(group)
	msg := sprintf(
		"AU-11: log group %q retains %d days, below the %d-day FedRAMP Moderate floor",
		[group.address, group.change.after.retention_in_days, moderate_minimum_days],
	)
}

deny contains msg if {
	some group in planned_resources("aws_cloudwatch_log_group")
	group.change.after.retention_in_days == 0
	msg := sprintf("AU-11: log group %q never expires; set an explicit retention period", [group.address])
}

# Delivery-pipeline diagnostics are not audit records. They exist to debug the
# pipeline and holding them for a year is waste, not compliance.
is_operational_log_group(group) if {
	contains(group.change.after.name, "kinesisfirehose")
}

# AU-9(3): Object Lock must be COMPLIANCE mode. GOVERNANCE mode can be bypassed
# by any principal holding s3:BypassGovernanceRetention, which makes it a
# suggestion rather than a control.
deny contains msg if {
	some lock in planned_resources("aws_s3_bucket_object_lock_configuration")
	some lock_rule in lock.change.after.rule
	some retention in lock_rule.default_retention
	retention.mode != "COMPLIANCE"
	msg := sprintf(
		"AU-9(3): %q uses Object Lock mode %q; COMPLIANCE is required for audit archives",
		[lock.address, retention.mode],
	)
}

deny contains msg if {
	some lock in planned_resources("aws_s3_bucket_object_lock_configuration")
	some lock_rule in lock.change.after.rule
	some retention in lock_rule.default_retention
	retention.days < moderate_minimum_days
	msg := sprintf(
		"AU-11: %q locks objects for %d days, below the %d-day floor",
		[lock.address, retention.days, moderate_minimum_days],
	)
}

# AU-9: versioning is a prerequisite for Object Lock and for recovering from an
# overwrite. A suspended-versioning archive bucket silently loses history.
deny contains msg if {
	some versioning in planned_resources("aws_s3_bucket_versioning")
	some vconfig in versioning.change.after.versioning_configuration
	vconfig.status != "Enabled"
	msg := sprintf("AU-9: %q does not have versioning Enabled (status %q)", [versioning.address, vconfig.status])
}

# AU-5: an alarm with no action is a dashboard widget. Every alarm this baseline
# creates has to reach a human or an incident queue.
deny contains msg if {
	some alarm in planned_resources("aws_cloudwatch_metric_alarm")
	count(object.get(alarm.change.after, "alarm_actions", [])) == 0
	msg := sprintf("AU-5/IR-4: alarm %q has no alarm_actions, so nothing is notified when it fires", [alarm.address])
}
