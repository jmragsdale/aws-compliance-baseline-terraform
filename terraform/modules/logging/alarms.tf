# ---------------------------------------------------------------------------
# CIS monitoring: metric filters and alarms.
#
# AU-6(1) and SI-4(4) require that audit records are *reviewed*, not merely
# retained. CIS AWS Foundations Benchmark v5.0 section 4 turns that into a
# concrete list: fifteen specific event patterns that must raise an alarm. This
# file implements all fifteen from one table, because writing them out
# individually is how one of them quietly goes missing.
#
# IR-4/IR-5: every alarm lands on a single SNS topic so incident response has
# one place to subscribe rather than fifteen.
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "security_alarms" {
  name = "${var.name_prefix}-security-alarms"

  # SC-28: alarm notifications quote the offending principal and API call, which
  # is exactly the reconnaissance an attacker would like. Encrypt at rest; fall
  # back to the AWS-managed SNS key when no CMK exists.
  kms_master_key_id = var.kms_key_arn != null ? var.kms_key_arn : "alias/aws/sns"

  tags = merge(local.tags, { Purpose = "security-alarms" })
}

data "aws_iam_policy_document" "security_alarms" {
  statement {
    sid       = "AllowCloudWatchAlarmsPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alarms.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # EventBridge publishes the evidence-pipeline failures and Security Hub
  # escalations onto the same topic.
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alarms.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # AU-5: log file delivery notifications from the trail land on the same topic
  # as the alarms, so incident response has one subscription rather than two.
  statement {
    sid       = "AllowCloudTrailDeliveryNotifications"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alarms.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish", "sns:Subscribe"]
    resources = [aws_sns_topic.security_alarms.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "security_alarms" {
  arn    = aws_sns_topic.security_alarms.arn
  policy = data.aws_iam_policy_document.security_alarms.json
}

# Email subscriptions require an out-of-band confirmation click, so this is
# created only when an address is supplied and is never a hard dependency of
# anything else.
resource "aws_sns_topic_subscription" "security_contact" {
  count = var.security_contact_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.security_alarms.arn
  protocol  = "email"
  endpoint  = var.security_contact_email
}

locals {
  # CIS AWS Foundations Benchmark v5.0, section 4. The `cis` key is carried into
  # the alarm description so an operator reading a page knows which benchmark
  # recommendation just fired and why anyone cares.
  monitored_events = {
    unauthorized-api-calls = {
      cis         = "4.1"
      description = "Unauthorized API calls (AccessDenied / UnauthorizedOperation). Sustained volume is credential probing."
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") && ($.sourceIPAddress != \"delivery.logs.amazonaws.com\") && ($.eventName != \"HeadBucket\") }"
    }
    console-signin-without-mfa = {
      cis         = "4.2"
      description = "Console sign-in without MFA. IA-2(1) makes this a finding on its own, not a warning."
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    root-account-usage = {
      cis         = "4.3"
      description = "Root account used. The root credential should be sealed; any use is an incident until proven otherwise (AC-6(9))."
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    iam-policy-changes = {
      cis         = "4.4"
      description = "IAM policy changed. Privilege boundaries moving without a change record is the classic escalation signature (AC-2, AC-6)."
      pattern     = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    }
    cloudtrail-config-changes = {
      cis         = "4.5"
      description = "CloudTrail configuration changed. AU-9: tampering with the audit mechanism is itself an auditable event."
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }
    console-auth-failures = {
      cis         = "4.6"
      description = "Failed console authentication. AC-7 (unsuccessful logon attempts)."
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    cmk-disable-or-delete = {
      cis         = "4.7"
      description = "Customer-managed key scheduled for deletion or disabled. Deleting a key destroys every object it protects (SC-12)."
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }
    s3-policy-changes = {
      cis         = "4.8"
      description = "S3 bucket policy or ACL changed. The most common route to accidental public data exposure (AC-3, SC-7)."
      pattern     = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }
    config-changes = {
      cis         = "4.9"
      description = "AWS Config recorder or delivery channel changed. Blinding Config blinds the whole detective layer (CM-8, SI-4)."
      pattern     = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }
    security-group-changes = {
      cis         = "4.10"
      description = "Security group rules changed. SC-7 boundary protection depends on these staying where the change record says they are."
      pattern     = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }
    nacl-changes = {
      cis         = "4.11"
      description = "Network ACL changed (SC-7)."
      pattern     = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }
    network-gateway-changes = {
      cis         = "4.12"
      description = "Internet or customer gateway changed. A new IGW in a private-only VPC is an exfiltration path (SC-7)."
      pattern     = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }
    route-table-changes = {
      cis         = "4.13"
      description = "Route table changed. Traffic silently rerouted around inspection is the point of this alarm (SC-7)."
      pattern     = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
    }
    vpc-changes = {
      cis         = "4.14"
      description = "VPC or peering configuration changed (SC-7, AC-4 information flow enforcement)."
      pattern     = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
    }
    organizations-changes = {
      cis         = "4.15"
      description = "AWS Organizations changed. Detaching an SCP or moving an account between OUs removes preventive controls wholesale."
      pattern     = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each = local.monitored_events

  name           = "${var.name_prefix}-${each.key}"
  pattern        = each.value.pattern
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "${var.name_prefix}-${each.key}"
    namespace = var.alarm_namespace
    value     = "1"
    # Without a default, a period with no matching events produces no datapoint
    # and the alarm sits in INSUFFICIENT_DATA forever, which looks identical to
    # "working fine" on a dashboard.
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.monitored_events

  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = "CIS AWS Foundations v5.0 ${each.value.cis}: ${each.value.description}"
  namespace           = var.alarm_namespace
  metric_name         = "${var.name_prefix}-${each.key}"
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]
  ok_actions    = []

  tags = merge(local.tags, { CISRecommendation = each.value.cis })
}

# AU-5: the audit system failing must itself raise an alarm. A trail that stops
# delivering is silent by construction, so this watches for the absence of
# delivery rather than for an error.
resource "aws_cloudwatch_metric_alarm" "trail_delivery_failure" {
  alarm_name          = "${var.name_prefix}-cloudtrail-delivery-stopped"
  alarm_description   = "AU-5: the organization trail has stopped delivering log records to CloudWatch Logs."
  namespace           = "AWS/Logs"
  metric_name         = "IncomingLogEvents"
  dimensions          = { LogGroupName = aws_cloudwatch_log_group.cloudtrail.name }
  statistic           = "Sum"
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = 3600
  evaluation_periods  = 3
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = local.tags
}
