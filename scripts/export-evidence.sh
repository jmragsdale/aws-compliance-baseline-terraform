#!/usr/bin/env bash
# Produce an auditor-ready evidence bundle from a live AWS account.
#
#   ./scripts/export-evidence.sh --out ./evidence-2026-08
#   ./scripts/export-evidence.sh --profile audit --region us-east-1 --athena
#
# What this is for
# ----------------
# Continuous monitoring (NIST 800-53 CA-7) means producing evidence on a
# schedule, not reconstructing it the week before an assessment. Every call
# below is read-only. Run it from the delegated security tooling account with a
# read-only role; nothing here needs write access to anything.
#
# What it produces
# ----------------
#   <out>/
#     manifest.json                 what was collected, when, by whom
#     securityhub-standards.json    which standards are subscribed
#     securityhub-controls.csv      per-control pass/fail with framework refs
#     securityhub-findings.json     open failed findings
#     config-compliance.csv         Config rule compliance across the org
#     config-conformance-packs.json conformance pack status
#     guardduty-findings.json       open GuardDuty findings by severity
#     cloudtrail-status.json        trail configuration and delivery status
#     access-analyzer-findings.json external and unused access findings
#     iam-credential-report.csv     the IAM credential report, verbatim
#     organizations-policies.json   SCPs and RCPs with their targets
#     athena-findings.csv           (--athena) historical query from the lake
#
# Honest caveat: this collects *technical* evidence. It says nothing about the
# administrative controls (AT, PS, PE, most of PL/PM) that make up a large part
# of any FedRAMP package, and an assessor will ask for those separately.
set -euo pipefail

OUT_DIR="./evidence-$(date -u +%Y%m%dT%H%M%SZ)"
PROFILE=""
REGION="${AWS_REGION:-us-east-1}"
RUN_ATHENA=false
ATHENA_WORKGROUP=""
ATHENA_DATABASE=""
LOOKBACK_DAYS=30

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --lookback-days) LOOKBACK_DAYS="$2"; shift 2 ;;
    --athena) RUN_ATHENA=true; shift ;;
    --workgroup) ATHENA_WORKGROUP="$2"; shift 2 ;;
    --database) ATHENA_DATABASE="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage 1 ;;
  esac
done

for tool in aws jq; do
  command -v "$tool" >/dev/null || { printf '%s is required\n' "$tool" >&2; exit 1; }
done

AWS=(aws --region "$REGION" --output json)
[ -n "$PROFILE" ] && AWS+=(--profile "$PROFILE")

mkdir -p "$OUT_DIR"

log()  { printf '\033[1m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m    skipped: %s\033[0m\n' "$1"; }

# A service that is switched off is a legitimate answer, not an error. Collect
# what exists and record what did not, rather than aborting halfway through.
collect() {
  local name="$1"; shift
  if "$@" >"$OUT_DIR/$name" 2>"$OUT_DIR/.$name.err"; then
    rm -f "$OUT_DIR/.$name.err"
    return 0
  fi
  warn "$name ($(head -c 200 "$OUT_DIR/.$name.err" | tr '\n' ' '))"
  rm -f "$OUT_DIR/$name" "$OUT_DIR/.$name.err"
  return 1
}

SINCE_EPOCH_MS=$(( ( $(date -u +%s) - LOOKBACK_DAYS * 86400 ) * 1000 ))

log "identity and scope"
"${AWS[@]}" sts get-caller-identity >"$OUT_DIR/caller-identity.json"
ACCOUNT_ID=$(jq -r '.Account' "$OUT_DIR/caller-identity.json")

# --------------------------------------------------------------- Security Hub

log "Security Hub standards and control results"
collect securityhub-standards.json \
  "${AWS[@]}" securityhub get-enabled-standards

# CA-7: the per-control pass/fail table is the single most useful artefact in
# this bundle. It maps directly onto the CIS and NIST control identifiers an
# assessor is working from.
if "${AWS[@]}" securityhub list-security-control-definitions >/dev/null 2>&1; then
  SUBSCRIPTION_ARNS=$(jq -r '.StandardsSubscriptions[].StandardsSubscriptionArn' \
    "$OUT_DIR/securityhub-standards.json" 2>/dev/null || true)

  printf 'standard_arn,control_id,title,status,severity,disabled_reason\n' \
    >"$OUT_DIR/securityhub-controls.csv"

  for arn in $SUBSCRIPTION_ARNS; do
    "${AWS[@]}" securityhub describe-standards-controls \
      --standards-subscription-arn "$arn" \
      --max-results 100 2>/dev/null \
    | jq -r --arg arn "$arn" '
        .Controls[]
        | [$arn, .ControlId, .Title, .ControlStatus, .SeverityRating,
           (.DisabledReason // "")]
        | @csv' >>"$OUT_DIR/securityhub-controls.csv" || true
  done
else
  warn "securityhub-controls.csv (Security Hub not enabled in $REGION)"
fi

# Open, failed, non-suppressed findings. Suppressed ones are deliberately
# excluded here and captured in the Athena export instead, where the
# suppression reason travels with the record.
collect securityhub-findings.json \
  "${AWS[@]}" securityhub get-findings \
    --max-results 100 \
    --filters "{
      \"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}],
      \"WorkflowStatus\":[{\"Value\":\"NEW\",\"Comparison\":\"EQUALS\"},
                          {\"Value\":\"NOTIFIED\",\"Comparison\":\"EQUALS\"}],
      \"ComplianceStatus\":[{\"Value\":\"FAILED\",\"Comparison\":\"EQUALS\"}]
    }"

# ---------------------------------------------------------------- AWS Config

log "AWS Config compliance (CM-8, CM-6)"
printf 'rule_name,compliance_type,non_compliant_resource_count\n' \
  >"$OUT_DIR/config-compliance.csv"

if "${AWS[@]}" configservice describe-config-rules >/dev/null 2>&1; then
  "${AWS[@]}" configservice describe-compliance-by-config-rule \
  | jq -r '
      .ComplianceByConfigRules[]
      | [.ConfigRuleName,
         .Compliance.ComplianceType,
         (.Compliance.ComplianceContributorCount.CappedCount // 0)]
      | @csv' >>"$OUT_DIR/config-compliance.csv"

  collect config-conformance-packs.json \
    "${AWS[@]}" configservice describe-conformance-pack-status

  # CM-8: the configuration recorder's own status is evidence. A recorder that
  # stopped six weeks ago invalidates every Config finding after that date.
  collect config-recorder-status.json \
    "${AWS[@]}" configservice describe-configuration-recorder-status
else
  warn "config-compliance.csv (Config not enabled in $REGION)"
fi

# ----------------------------------------------------------------- GuardDuty

log "GuardDuty findings (SI-4)"
DETECTOR_ID=$("${AWS[@]}" guardduty list-detectors 2>/dev/null \
  | jq -r '.DetectorIds[0] // empty')

if [ -n "$DETECTOR_ID" ]; then
  FINDING_IDS=$("${AWS[@]}" guardduty list-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-criteria "{\"Criterion\":{\"service.archived\":{\"Eq\":[\"false\"]},\"updatedAt\":{\"Gte\":$SINCE_EPOCH_MS}}}" \
    --max-results 50 2>/dev/null | jq -r '.FindingIds | join(" ")')

  if [ -n "$FINDING_IDS" ]; then
    # shellcheck disable=SC2086
    "${AWS[@]}" guardduty get-findings \
      --detector-id "$DETECTOR_ID" \
      --finding-ids $FINDING_IDS >"$OUT_DIR/guardduty-findings.json"
  else
    printf '{"Findings":[]}\n' >"$OUT_DIR/guardduty-findings.json"
  fi
else
  warn "guardduty-findings.json (no detector in $REGION)"
fi

# ---------------------------------------------------------------- CloudTrail

log "CloudTrail configuration and delivery status (AU-2, AU-9)"
collect cloudtrail-trails.json "${AWS[@]}" cloudtrail describe-trails

if [ -f "$OUT_DIR/cloudtrail-trails.json" ]; then
  # AU-9: LatestDeliveryError being non-empty means the audit trail has a hole
  # in it. This is the field nobody checks until an assessor does.
  jq -c '.trailList[] | {Name, TrailARN, HomeRegion}' "$OUT_DIR/cloudtrail-trails.json" \
  | while read -r trail; do
      name=$(printf '%s' "$trail" | jq -r '.Name')
      "${AWS[@]}" cloudtrail get-trail-status --name "$name" 2>/dev/null \
      | jq --argjson t "$trail" '. + {Trail: $t}'
    done | jq -s '.' >"$OUT_DIR/cloudtrail-status.json"
fi

# ------------------------------------------------------------ Access Analyzer

log "IAM Access Analyzer findings (AC-3, AC-6)"
: >"$OUT_DIR/access-analyzer-findings.json"
ANALYZER_ARNS=$("${AWS[@]}" accessanalyzer list-analyzers 2>/dev/null \
  | jq -r '.analyzers[].arn' || true)

if [ -n "$ANALYZER_ARNS" ]; then
  for analyzer in $ANALYZER_ARNS; do
    "${AWS[@]}" accessanalyzer list-findings-v2 \
      --analyzer-arn "$analyzer" \
      --filter '{"status":{"eq":["ACTIVE"]}}' \
      --max-results 100 2>/dev/null \
    | jq --arg a "$analyzer" '{analyzer: $a, findings: .findings}'
  done | jq -s '.' >"$OUT_DIR/access-analyzer-findings.json"
else
  warn "access-analyzer-findings.json (no analyzers in $REGION)"
  rm -f "$OUT_DIR/access-analyzer-findings.json"
fi

# ------------------------------------------------------------------- IAM / org

log "IAM credential report (IA-5, AC-2)"
# The report is generated asynchronously; STARTED means "come back in a moment".
"${AWS[@]}" iam generate-credential-report >/dev/null 2>&1 || true
for _ in 1 2 3 4 5; do
  if "${AWS[@]}" iam get-credential-report >"$OUT_DIR/.cred.json" 2>/dev/null; then
    jq -r '.Content' "$OUT_DIR/.cred.json" | base64 -d >"$OUT_DIR/iam-credential-report.csv"
    rm -f "$OUT_DIR/.cred.json"
    break
  fi
  sleep 3
done
[ -f "$OUT_DIR/iam-credential-report.csv" ] || warn "iam-credential-report.csv"

log "Organizations policies and targets (CM-7, AC-3)"
if "${AWS[@]}" organizations describe-organization >/dev/null 2>&1; then
  {
    for policy_type in SERVICE_CONTROL_POLICY RESOURCE_CONTROL_POLICY; do
      "${AWS[@]}" organizations list-policies --filter "$policy_type" 2>/dev/null \
      | jq -r '.Policies[].Id' \
      | while read -r pid; do
          content=$("${AWS[@]}" organizations describe-policy --policy-id "$pid")
          targets=$("${AWS[@]}" organizations list-targets-for-policy --policy-id "$pid")
          printf '%s' "$content" | jq --argjson t "$targets" \
            --arg type "$policy_type" \
            '{type: $type, policy: .Policy.PolicySummary, content: .Policy.Content, targets: $t.Targets}'
        done
    done
  } | jq -s '.' >"$OUT_DIR/organizations-policies.json"
else
  warn "organizations-policies.json (not an Organizations management or delegated account)"
fi

# ---------------------------------------------------------- Athena (optional)

# AU-7: Security Hub only keeps 90 days. Anything older than that has to come
# from the evidence lake, which is what --athena queries.
if [ "$RUN_ATHENA" = true ]; then
  log "Athena historical query against the evidence lake (AU-7, AU-11)"
  if [ -z "$ATHENA_WORKGROUP" ] || [ -z "$ATHENA_DATABASE" ]; then
    warn "athena-findings.csv (--workgroup and --database are required with --athena)"
  else
    QUERY="SELECT f.awsaccountid AS account_id,
       f.severity.label AS severity,
       f.compliance.securitycontrolid AS control_id,
       f.compliance.status AS status,
       f.title,
       f.updatedat AS last_seen
FROM security_hub_findings
CROSS JOIN UNNEST(detail.findings) AS t(f)
WHERE f.recordstate = 'ACTIVE'
  AND f.compliance.status = 'FAILED'
ORDER BY f.severity.normalized DESC
LIMIT 5000"

    EXEC_ID=$("${AWS[@]}" athena start-query-execution \
      --query-string "$QUERY" \
      --work-group "$ATHENA_WORKGROUP" \
      --query-execution-context "Database=$ATHENA_DATABASE" \
      | jq -r '.QueryExecutionId')

    for _ in $(seq 1 60); do
      STATE=$("${AWS[@]}" athena get-query-execution --query-execution-id "$EXEC_ID" \
        | jq -r '.QueryExecution.Status.State')
      case "$STATE" in
        SUCCEEDED) break ;;
        FAILED|CANCELLED)
          warn "athena-findings.csv (query $STATE)"
          break ;;
      esac
      sleep 5
    done

    if [ "${STATE:-}" = "SUCCEEDED" ]; then
      RESULT_PATH=$("${AWS[@]}" athena get-query-execution --query-execution-id "$EXEC_ID" \
        | jq -r '.QueryExecution.ResultConfiguration.OutputLocation')
      "${AWS[@]}" s3 cp "$RESULT_PATH" "$OUT_DIR/athena-findings.csv" >/dev/null
    fi
  fi
fi

# ------------------------------------------------------------------- manifest

# The manifest is what makes the bundle self-describing six months from now.
# An evidence package with no provenance is an assertion, not evidence.
log "manifest"
jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg account_id "$ACCOUNT_ID" \
  --arg region "$REGION" \
  --arg lookback_days "$LOOKBACK_DAYS" \
  --arg tool "aws-compliance-baseline-terraform/scripts/export-evidence.sh" \
  --argjson caller "$(cat "$OUT_DIR/caller-identity.json")" \
  --argjson files "$(cd "$OUT_DIR" && ls -1 | jq -R . | jq -s .)" \
  '{
     generated_at: $generated_at,
     collected_by: $tool,
     account_id: $account_id,
     region: $region,
     guardduty_lookback_days: ($lookback_days | tonumber),
     caller: $caller,
     files: $files,
     scope_note: "Technical control evidence only. Administrative and procedural control families (AT, PS, PE, and much of PL/PM) are collected outside this tool.",
     integrity_note: "This bundle is a point-in-time read. The authoritative, tamper-evident record is the Object Lock archive in S3; these files are a convenience extract."
   }' >"$OUT_DIR/manifest.json"

log "done -> $OUT_DIR"
find "$OUT_DIR" -maxdepth 1 -type f -printf '    %-36s %8s bytes\n' 2>/dev/null \
  || ls -la "$OUT_DIR"
