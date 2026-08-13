# Development Log - aws-compliance-baseline-terraform

Working notes: decisions, dead ends, and the reasoning behind the shape of this repo.

## 2026-08-13 - Initial build

**Why a `controls.yaml` instead of prose in the README.**
Compliance repos usually claim framework coverage in a README table that nothing
verifies. The table drifts from the code within a release or two and there is no
signal when it does. Here the matrix is generated from `controls/controls.yaml`,
each control names the Terraform address implementing it, and CI fails the build
if that address stops existing. The claim and the code cannot separate silently.

**Why plan-only verification.**
Org-scoped resources cannot be applied without owning an organization. Rather
than pretend otherwise, CI runs `terraform init -backend=false` + `validate` and
static analysis only. The README states plainly which controls are plan-verified
versus apply-verified. Overclaiming here is the fastest way to lose credibility
with anyone who has actually sat through an assessment.

**Why FedRAMP baseline is a variable, not a fork.**
Moderate and High differ mostly in parameter values (retention windows, MFA
scope, encryption strength, availability requirements) rather than in which
controls exist. `var.fedramp_baseline` drives those parameters so the two
baselines share one code path and stay in sync.

**Scope honesty.**
This repo implements *technical* controls. FedRAMP and NIST 800-53 include large
administrative and procedural families - awareness and training, personnel
security, physical protection, most of planning and program management - that no
amount of Terraform will satisfy. The generated coverage percentages count
technical controls only and `CONTROLS.md` says so at the top.

## 2026-08-13 - AWS build notes

**Five SCPs, not fifteen.** The first draft had one `aws_organizations_policy`
per guardrail: deny root, deny access keys, deny unencrypted PUT, and so on.
Eleven policies, one control each, a beautifully granular control matrix - and
completely unattachable, because AWS Organizations allows a maximum of five SCPs
per root, OU or account. The failure mode is the worst kind: the plan succeeds,
the apply gets partway through the attachments and then throws a quota error,
leaving the organization half-guarded. Rewrote as five themed bundles (identity,
audit, data, region, compute) with one `Sid` per statement so a Deny in
CloudTrail still names the specific guardrail. Added a `check` block that fails
the plan if the bundle count ever exceeds five, plus the same assertion in
`policies/guardrails.rego` against plan JSON. Several controls in CONTROLS.md now
point at the same Terraform address, which is honest: they are statements in one
document, not separate resources.

**RCPs were the interesting half.** SCPs are what everyone builds. They answer
"what can our principals do". They do not answer "what can a principal in an
account we have never heard of do to our bucket", which is the question an
assessor asks about AC-21 and information sharing. Resource control policies are
the other half and they are new enough that most baselines predate them. Worth
being precise about the limit though: RCPs cover S3, STS, KMS, SQS and Secrets
Manager and nothing else, so calling it a total data perimeter would be wrong.
That caveat is in ORG-009's notes rather than buried.

**Break-glass exemptions, deliberately.** Every deny statement exempts the roles
in `var.break_glass_role_names`. This weakens each guardrail and it is still the
right call - an SCP set with no escape hatch has locked administrators out of
entire organizations, and the recovery path involves AWS Support and a week you
will not enjoy. The mitigation is that the exemption is monitored: the CIS
metric filters alarm on CloudTrail and Config configuration changes regardless of
who made them, so using break-glass is loud. `policies/guardrails.rego` asserts
the exemption exists, which felt backwards to write and is correct.

**Object Lock is a one-way door and it fights Terraform.** COMPLIANCE mode cannot
be shortened or bypassed by anyone including the account root and AWS Support.
That is exactly what AU-9 wants and it means `terraform destroy` on the archive
bucket does not work - and the bucket policy denies `DeleteBucket` outright, with
no break-glass exemption, on purpose. Two things fell out of that: the lifecycle
expiration is set to `object_lock_days + 1` (set it earlier and S3 refuses every
delete, generating noise and no savings), and the replica gets its *own* Object
Lock configuration, because replication copies objects and not bucket-level
protections. A replica without Object Lock is a deletable copy of an undeletable
archive, which is worse than no replica because it looks like protection.

**Conformance packs: trimmed on purpose.** The AWS-published FedRAMP pack is
around 150 rules and several thousand lines of CloudFormation. Vendoring it
would have inflated the repo and, more to the point, nobody reviews a
three-thousand-line template - and unreviewed rules produce unreviewed findings
that get bulk-suppressed six weeks later. Hand-wrote 25/35/24-rule subsets where
every rule maps to a control this repo also implements preventively, so a finding
means a guardrail was bypassed rather than never existed. DET-008's notes say
plainly that these are not the full packs and where to get them.

**The single-provider simplification.** Delegated-administrator resources
(`aws_securityhub_organization_admin_account`, the GuardDuty and Macie
equivalents) are called from the management account, while
`aws_securityhub_account` and the standards subscriptions belong in the security
tooling account. Doing that properly needs two aliased providers assuming two
roles. This repo declares them under one provider, which plans fine and would
need splitting before a real apply. Called out in the README's not-verified
section rather than left for someone to discover.

**Checkov: what got fixed versus accepted.** Real fixes came out of it - an
unfiltered abort-incomplete-multipart-upload lifecycle rule on the evidence
bucket (Firehose leaves billable, invisible parts on failed uploads), a lifecycle
configuration on the replica so it tiers the same way as the primary, and a
CloudTrail SNS delivery notification with the matching topic policy statement.
The rest are accepted with written inline reasons: a KMS key policy's
`Resource: "*"` means "this key" and cannot name its own ARN without
circularity; S3 server access log delivery genuinely cannot write into a
CMK-encrypted bucket; a VPC endpoint policy is not an identity policy and cannot
grant anything; several graph checks cannot follow a reference across a `count`
index. Each of those is an inline `checkov:skip` with prose, because a skip list
with no reasons is how a compliance repo quietly stops being one.

**The `enable_*`-everything default.** Every metered service defaults to false,
which means the out-of-the-box plan does almost nothing. That felt wrong for
about a day and then felt obviously right: someone evaluating this should be able
to run `terraform plan` against a real account without wondering what it will
cost, and the two examples show the intended production combinations. The two
`check` blocks in the root module catch the corresponding failure mode - claiming
`fedramp_baseline = "high"` while the detective layer is switched off, which
reads fine in a tfvars file and badly in an SSP.
