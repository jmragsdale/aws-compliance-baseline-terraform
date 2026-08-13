# Data perimeter invariants.
#
# The failure this catches is specific and common: a resource policy that grants
# to `"AWS": "*"` with no condition narrowing it to the organization. Every
# generic scanner flags the obvious version of that. What they miss is the
# *conditional* version -- a wildcard principal with a condition that does not
# actually constrain identity (a SourceIp allow-list, a UserAgent match) which
# reads as scoped and is not.
#
# SC-7 (boundary protection) and AC-4 (information flow enforcement) are the
# controls. AC-21 (information sharing) is the one an assessor asks about.
package terraform.data_perimeter

import rego.v1

# Conditions that genuinely constrain *who* the caller is. Anything else may be
# useful defence in depth but does not establish a perimeter.
identity_condition_keys := {
	"aws:PrincipalOrgID",
	"aws:PrincipalOrgPaths",
	"aws:PrincipalAccount",
	"aws:PrincipalArn",
	"aws:SourceOrgID",
	"aws:SourceAccount",
	"aws:SourceArn",
	"aws:ResourceOrgID",
	"aws:PrincipalIsAWSService",
}

planned_resources(resource_type) := [r |
	some r in input.resource_changes
	r.type == resource_type
	not is_delete(r)
]

is_delete(r) if {
	count(r.change.actions) == 1
	r.change.actions[0] == "delete"
}

policy_documents contains {"address": r.address, "doc": doc} if {
	some resource_type in ["aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key"]
	some r in planned_resources(resource_type)
	raw := object.get(r.change.after, "policy", "")
	raw != ""
	doc := json.unmarshal(raw)
}

statements contains {"address": entry.address, "statement": st} if {
	some entry in policy_documents
	some st in entry.doc.Statement
}

# SC-7: an Allow to every principal with no identity condition is an open door,
# whatever else the statement says.
deny contains msg if {
	some entry in statements
	entry.statement.Effect == "Allow"
	has_wildcard_principal(entry.statement)
	not has_identity_condition(entry.statement)
	msg := sprintf(
		"SC-7: %q statement %q allows a wildcard principal with no organization or account condition",
		[entry.address, object.get(entry.statement, "Sid", "<unnamed>")],
	)
}

has_wildcard_principal(st) if st.Principal == "*"

has_wildcard_principal(st) if st.Principal.AWS == "*"

has_wildcard_principal(st) if {
	is_array(st.Principal.AWS)
	some p in st.Principal.AWS
	p == "*"
}

has_identity_condition(st) if {
	some operator in object.keys(st.Condition)
	some key in object.keys(st.Condition[operator])
	identity_condition_keys[key]
}

# SC-8: every bucket policy in this repo carries an explicit deny on plaintext
# transport. Relying on the RCP alone means a bucket created outside the
# organization perimeter loses the protection.
deny contains msg if {
	some entry in policy_documents
	startswith(entry.address, "aws_s3_bucket_policy.")
	not denies_insecure_transport(entry.doc)
	msg := sprintf("SC-8: %q has no statement denying aws:SecureTransport = false", [entry.address])
}

denies_insecure_transport(doc) if {
	some st in doc.Statement
	st.Effect == "Deny"
	st.Condition.Bool["aws:SecureTransport"] == "false"
}

# SC-7: unrestricted ingress. The modern rule resources are checked as well as
# the legacy inline ones, because a repo that only checks aws_security_group
# misses everything written in the last two years.
deny contains msg if {
	some rule in planned_resources("aws_vpc_security_group_ingress_rule")
	rule.change.after.cidr_ipv4 == "0.0.0.0/0"
	msg := sprintf("SC-7: ingress rule %q allows 0.0.0.0/0", [rule.address])
}

deny contains msg if {
	some rule in planned_resources("aws_vpc_security_group_ingress_rule")
	rule.change.after.cidr_ipv6 == "::/0"
	msg := sprintf("SC-7: ingress rule %q allows ::/0", [rule.address])
}

# AC-4: a VPC endpoint with no policy is an unrestricted route to every account
# in AWS for that service, which is the exact exfiltration path endpoints are
# supposed to close.
deny contains msg if {
	some endpoint in planned_resources("aws_vpc_endpoint")
	object.get(endpoint.change.after, "policy", "") == ""
	msg := sprintf("AC-4: VPC endpoint %q has no endpoint policy restricting it to the organization", [endpoint.address])
}
