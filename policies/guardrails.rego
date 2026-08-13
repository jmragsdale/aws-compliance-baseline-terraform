# Preventive guardrail invariants.
#
# The SCP set is the load-bearing part of this baseline: if a guardrail is
# dropped during a refactor, nothing else in the repo notices. Config and
# Security Hub will not report a *missing* SCP, only a resource that violated
# one, and the resource will not violate it because the SCP is gone.
#
# So the guardrails are asserted structurally: the required Sids must be
# present, the region allow-list must be non-empty, and the attachment count per
# target must respect the Organizations quota that would otherwise fail the
# apply halfway through.
#
# NIST 800-53 CM-7 (least functionality), AC-3 (access enforcement), AU-9.
package terraform.guardrails

import rego.v1

# Every Sid the control matrix claims exists. Adding a control to
# controls/controls.yaml without adding its Sid here is caught by review; the
# reverse -- deleting the statement -- is caught by this policy.
required_sids := {
	"DenyRootAccountUsage",
	"DenyIamUserAccessKeyCreation",
	"DenyDisablingSecurityServices",
	"DenyLeavingOrganization",
	"DenyUnencryptedS3Put",
	"DenyUnencryptedEbs",
	"DenyPublicS3Access",
	"DenyOperationsOutsideApprovedRegions",
	"DenyRunInstancesWithoutImdsv2",
}

max_policies_per_target := 5

planned_resources(resource_type) := [r |
	some r in input.resource_changes
	r.type == resource_type
	not is_delete(r)
]

is_delete(r) if {
	count(r.change.actions) == 1
	r.change.actions[0] == "delete"
}

org_policies := planned_resources("aws_organizations_policy")

present_sids contains sid if {
	some policy in org_policies
	doc := json.unmarshal(policy.change.after.content)
	some st in doc.Statement
	sid := st.Sid
}

# CM-7: a guardrail that was deleted rather than deliberately retired.
deny contains msg if {
	count(org_policies) > 0
	some sid in required_sids
	not present_sids[sid]
	msg := sprintf("CM-7: required guardrail statement %q is not present in any organizations policy", [sid])
}

# AC-3: an SCP statement with Effect Allow does not restrict anything -- SCPs
# are filters, not grants -- and its presence usually means someone has
# misunderstood what the policy does.
deny contains msg if {
	some policy in org_policies
	policy.change.after.type == "SERVICE_CONTROL_POLICY"
	doc := json.unmarshal(policy.change.after.content)
	some st in doc.Statement
	st.Effect == "Allow"
	st.Action == "*"
	msg := sprintf(
		"AC-3: %q contains a blanket Allow statement; SCPs filter permissions and a blanket Allow is a no-op that reads as a grant",
		[policy.address],
	)
}

# CA-9: an empty region allow-list denies every regional API call in the
# organization. This is the single most destructive typo available here.
deny contains msg if {
	some policy in org_policies
	doc := json.unmarshal(policy.change.after.content)
	some st in doc.Statement
	st.Sid == "DenyOperationsOutsideApprovedRegions"
	count(st.Condition.StringNotEquals["aws:RequestedRegion"]) == 0
	msg := sprintf("CA-9: %q denies every region -- the allowed_regions list is empty", [policy.address])
}

# Every deny guardrail must exempt a break-glass principal. Recovering an
# organization that denied its own administrators requires an AWS Support case
# and takes days.
deny contains msg if {
	some policy in org_policies
	policy.change.after.type == "SERVICE_CONTROL_POLICY"
	doc := json.unmarshal(policy.change.after.content)
	some st in doc.Statement
	st.Sid == "DenyDisablingSecurityServices"
	not has_break_glass_exemption(st)
	msg := sprintf("%q denies security service changes with no break-glass exemption", [policy.address])
}

# count() works on both a list of ARNs and a single ARN string, so one rule
# covers the two shapes an IAM condition value can take.
has_break_glass_exemption(st) if {
	count(st.Condition.StringNotLike["aws:PrincipalArn"]) > 0
}

# Organizations allows at most 5 policies of each type attached to any single
# root, OU or account. Exceeding it fails at apply time, after some attachments
# have already been made, which leaves the organization half-guarded.
attachment_targets contains target if {
	some a in planned_resources("aws_organizations_policy_attachment")
	target := a.change.after.target_id
}

attachment_count(target) := count([a |
	some a in planned_resources("aws_organizations_policy_attachment")
	a.change.after.target_id == target
])

deny contains msg if {
	some target in attachment_targets
	total := attachment_count(target)
	total > max_policies_per_target
	msg := sprintf(
		"target %q would receive %d policy attachments; AWS Organizations allows %d per target",
		[target, total, max_policies_per_target],
	)
}
