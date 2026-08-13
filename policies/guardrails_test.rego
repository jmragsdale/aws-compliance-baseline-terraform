package terraform.guardrails

import rego.v1

plan(resources) := {"resource_changes": resources}

scp(name, statements) := {
	"address": name,
	"type": "aws_organizations_policy",
	"change": {
		"actions": ["create"],
		"after": {
			"type": "SERVICE_CONTROL_POLICY",
			"content": json.marshal({"Version": "2012-10-17", "Statement": statements}),
		},
	},
}

attachment(name, policy_id, target) := {
	"address": name,
	"type": "aws_organizations_policy_attachment",
	"change": {"actions": ["create"], "after": {"policy_id": policy_id, "target_id": target}},
}

break_glass := {"StringNotLike": {"aws:PrincipalArn": ["arn:aws:iam::*:role/OrganizationBreakGlass"]}}

complete_statements := [
	{"Sid": "DenyRootAccountUsage", "Effect": "Deny", "Action": "*", "Resource": "*"},
	{"Sid": "DenyIamUserAccessKeyCreation", "Effect": "Deny", "Action": "iam:CreateAccessKey", "Resource": "*"},
	{
		"Sid": "DenyDisablingSecurityServices",
		"Effect": "Deny",
		"Action": "cloudtrail:StopLogging",
		"Resource": "*",
		"Condition": break_glass,
	},
	{"Sid": "DenyLeavingOrganization", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"},
	{"Sid": "DenyUnencryptedS3Put", "Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"},
	{"Sid": "DenyUnencryptedEbs", "Effect": "Deny", "Action": "ec2:CreateVolume", "Resource": "*"},
	{"Sid": "DenyPublicS3Access", "Effect": "Deny", "Action": "s3:PutAccountPublicAccessBlock", "Resource": "*"},
	{
		"Sid": "DenyOperationsOutsideApprovedRegions",
		"Effect": "Deny",
		"NotAction": ["iam:*"],
		"Resource": "*",
		"Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
	},
	{"Sid": "DenyRunInstancesWithoutImdsv2", "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*"},
]

# --- required statements ---------------------------------------------------

test_complete_guardrail_set_passes if {
	count(deny) == 0 with input as plan([scp("aws_organizations_policy.bundle", complete_statements)])
}

test_missing_root_guardrail_denied if {
	trimmed := [st | some st in complete_statements; st.Sid != "DenyRootAccountUsage"]
	count(deny) == 1 with input as plan([scp("aws_organizations_policy.bundle", trimmed)])
}

test_no_org_policies_at_all_is_not_flagged if {
	# single_account mode creates no Organizations policies; that is a valid
	# deployment shape, not a missing guardrail.
	count(deny) == 0 with input as plan([])
}

# --- blanket allow ---------------------------------------------------------

test_blanket_allow_statement_denied if {
	statements := array.concat(complete_statements, [{"Sid": "AllowEverything", "Effect": "Allow", "Action": "*", "Resource": "*"}])
	count(deny) == 1 with input as plan([scp("aws_organizations_policy.bundle", statements)])
}

# --- empty region allow-list ----------------------------------------------

test_empty_region_allowlist_denied if {
	statements := [st |
		some original in complete_statements
		st := empty_region_variant(original)
	]
	count(deny) == 1 with input as plan([scp("aws_organizations_policy.region", statements)])
}

empty_region_variant(st) := out if {
	st.Sid == "DenyOperationsOutsideApprovedRegions"
	out := json.patch(st, [{"op": "replace", "path": "/Condition/StringNotEquals/aws:RequestedRegion", "value": []}])
}

empty_region_variant(st) := st if st.Sid != "DenyOperationsOutsideApprovedRegions"

# --- break-glass exemption -------------------------------------------------

test_missing_break_glass_exemption_denied if {
	statements := [st |
		some original in complete_statements
		st := strip_break_glass(original)
	]
	count(deny) == 1 with input as plan([scp("aws_organizations_policy.audit", statements)])
}

strip_break_glass(st) := out if {
	st.Sid == "DenyDisablingSecurityServices"
	out := object.remove(st, ["Condition"])
}

strip_break_glass(st) := st if st.Sid != "DenyDisablingSecurityServices"

# --- attachment quota ------------------------------------------------------

test_five_attachments_per_target_passes if {
	attachments := [attachment(sprintf("a%d", [i]), sprintf("p-%d", [i]), "r-exam") | some i in [1, 2, 3, 4, 5]]
	resources := array.concat([scp("aws_organizations_policy.bundle", complete_statements)], attachments)
	count(deny) == 0 with input as plan(resources)
}

test_six_attachments_per_target_denied if {
	attachments := [attachment(sprintf("a%d", [i]), sprintf("p-%d", [i]), "r-exam") | some i in [1, 2, 3, 4, 5, 6]]
	resources := array.concat([scp("aws_organizations_policy.bundle", complete_statements)], attachments)
	count(deny) == 1 with input as plan(resources)
}

test_quota_is_per_target_not_global if {
	first := [attachment(sprintf("a%d", [i]), sprintf("p-%d", [i]), "ou-aaaa") | some i in [1, 2, 3, 4, 5]]
	second := [attachment(sprintf("b%d", [i]), sprintf("p-%d", [i]), "ou-bbbb") | some i in [1, 2, 3, 4, 5]]
	resources := array.concat(array.concat([scp("aws_organizations_policy.bundle", complete_statements)], first), second)
	count(deny) == 0 with input as plan(resources)
}
