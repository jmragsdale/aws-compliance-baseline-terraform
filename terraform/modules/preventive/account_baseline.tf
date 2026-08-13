# ---------------------------------------------------------------------------
# Account-level hardening.
#
# These four settings are account-scoped rather than organization-scoped, so
# they run in every deployment shape including single_account. They are the
# controls that an SCP can only protect, not create: an SCP can stop someone
# turning Block Public Access off, but something has to turn it on first.
# ---------------------------------------------------------------------------

# CIS 2.1.4 / AC-3: the account-level switch overrides every bucket-level
# setting, which means a bucket created by a Terraform module you have never
# reviewed still cannot be made public.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CIS 2.2.1 / SC-28: every EBS volume created in this account and region is
# encrypted whether or not the caller asked. Paired with the SCP that denies
# turning it off, this is a genuine "cannot happen" rather than a default.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# SC-12: pointing the default at a customer-managed key means volume encryption
# is revocable and its use is logged per-grant. The AWS-managed aws/ebs key
# offers neither.
resource "aws_ebs_default_kms_key" "this" {
  count = var.ebs_default_kms_key_id != null ? 1 : 0

  key_arn = var.ebs_default_kms_key_id
}

# IA-5(1): password composition and lifetime. The values come from the FedRAMP
# baseline table rather than being hard-coded, because Moderate and High
# disagree about length and maximum age.
#
# There is no MFA setting here because IAM has none at the account level -- MFA
# enforcement lives in the identity SCP above and in Identity Center, and
# claiming otherwise would be a hole in an SSP.
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.password_min_length
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = var.password_max_age_days
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = false
}
