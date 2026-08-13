# ---------------------------------------------------------------------------
# Glue catalog and Athena workgroup.
#
# AU-7 (audit record reduction and report generation). The catalog is what
# turns a bucket of gzipped JSON into something an auditor can query without
# involving an engineer, and the workgroup is what stops that query costing
# more than the assessment.
#
# Partition projection rather than a Glue crawler: a crawler is a scheduled job
# that costs money, lags behind reality, and is one more thing that can fail
# silently. Projection derives the partitions from the prefix pattern Firehose
# already writes, so a partition exists the moment an object lands in it.
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_database" "evidence" {
  name        = replace("${var.name_prefix}_evidence", "-", "_")
  description = "Security Hub findings retained beyond the 90-day console window (CA-7, AU-7, AU-11)"
}

resource "aws_glue_catalog_table" "findings" {
  name          = "security_hub_findings"
  database_name = aws_glue_catalog_database.evidence.name
  description   = "ASFF findings as delivered by EventBridge and Firehose."
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL             = "TRUE"
    classification       = "json"
    "projection.enabled" = "true"

    # Range is deliberately open-ended at the front: the lake starts when the
    # pipeline is switched on and the end date moves with the query.
    "projection.year.type"   = "integer"
    "projection.year.range"  = "2024,2035"
    "projection.year.digits" = "4"

    "projection.month.type"   = "integer"
    "projection.month.range"  = "1,12"
    "projection.month.digits" = "2"

    "projection.day.type"   = "integer"
    "projection.day.range"  = "1,31"
    "projection.day.digits" = "2"

    "storage.location.template" = "s3://${aws_s3_bucket.evidence.id}/${local.findings_prefix}/year=$${year}/month=$${month}/day=$${day}/"
  }

  partition_keys {
    name = "year"
    type = "string"
  }

  partition_keys {
    name = "month"
    type = "string"
  }

  partition_keys {
    name = "day"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.evidence.id}/${local.findings_prefix}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    compressed    = true

    ser_de_info {
      name                  = "asff-json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "ignore.malformed.json" = "true"
        # The EventBridge envelope uses hyphenated keys that Hive cannot
        # represent; this maps them onto legal column names.
        "mapping.detail_type" = "detail-type"
      }
    }

    # A deliberately shallow projection of ASFF. The full schema is ~200 nested
    # fields and changes as AWS adds services; the columns here are the ones an
    # assessment question actually touches, and the raw `detail` struct is kept
    # so nothing is lost.
    columns {
      name = "version"
      type = "string"
    }

    columns {
      name = "id"
      type = "string"
    }

    columns {
      name = "detail_type"
      type = "string"
    }

    columns {
      name = "source"
      type = "string"
    }

    columns {
      name = "account"
      type = "string"
    }

    columns {
      name = "time"
      type = "string"
    }

    columns {
      name = "region"
      type = "string"
    }

    columns {
      name    = "detail"
      type    = "struct<findings:array<struct<Id:string,ProductArn:string,GeneratorId:string,AwsAccountId:string,Types:array<string>,FirstObservedAt:string,LastObservedAt:string,CreatedAt:string,UpdatedAt:string,Severity:struct<Label:string,Normalized:int>,Title:string,Description:string,Remediation:struct<Recommendation:struct<Text:string,Url:string>>,ProductFields:map<string,string>,Resources:array<struct<Type:string,Id:string,Partition:string,Region:string>>,Compliance:struct<Status:string,RelatedRequirements:array<string>,SecurityControlId:string>,WorkflowState:string,Workflow:struct<Status:string>,RecordState:string>>>"
      comment = "ASFF payload. Compliance.RelatedRequirements carries the framework control ids the finding maps to."
    }
  }
}

# The auditor-facing workgroup. Separate from any analytics workgroup so its
# result location, encryption and cost ceiling are set by this repo rather than
# inherited from whatever the data team configured.
resource "aws_athena_workgroup" "auditor" {
  name        = "${var.name_prefix}-auditor"
  description = "Read-only evidence queries for assessors and continuous monitoring reports (AU-7)"
  state       = "ENABLED"

  configuration {
    # AC-3: settings below cannot be overridden per-query by the client, so an
    # auditor cannot accidentally write results into an unencrypted bucket.
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    # Cost guardrail. Without it, one `SELECT * FROM security_hub_findings`
    # against a year of data is a four-figure line item.
    bytes_scanned_cutoff_per_query = var.athena_bytes_scanned_cutoff

    result_configuration {
      output_location = "s3://${aws_s3_bucket.evidence.id}/${local.athena_results}/"

      encryption_configuration {
        encryption_option = local.use_cmk ? "SSE_KMS" : "SSE_S3"
        kms_key_arn       = var.kms_key_arn
      }
    }
  }

  tags = local.tags
}

# AU-7: the queries an assessor actually asks, saved so nobody has to
# reconstruct them under time pressure. These are also what
# scripts/export-evidence.sh runs.
resource "aws_athena_named_query" "open_critical_findings" {
  name        = "${var.name_prefix}-open-critical-findings"
  description = "Every currently-open CRITICAL or HIGH finding, newest first."
  workgroup   = aws_athena_workgroup.auditor.name
  database    = aws_glue_catalog_database.evidence.name

  query = <<-SQL
    SELECT
      f.awsaccountid            AS account_id,
      f.severity.label          AS severity,
      f.compliance.securitycontrolid AS control_id,
      f.title,
      f.updatedat               AS last_seen
    FROM ${aws_glue_catalog_database.evidence.name}.security_hub_findings
    CROSS JOIN UNNEST(detail.findings) AS t(f)
    WHERE year = '2026'
      AND f.recordstate = 'ACTIVE'
      AND f.workflow.status IN ('NEW', 'NOTIFIED')
      AND f.severity.label IN ('CRITICAL', 'HIGH')
    ORDER BY f.updatedat DESC
  SQL
}

resource "aws_athena_named_query" "control_coverage_by_framework" {
  name        = "${var.name_prefix}-control-coverage-by-framework"
  description = "Pass/fail counts per mapped framework requirement -- the continuous monitoring report."
  workgroup   = aws_athena_workgroup.auditor.name
  database    = aws_glue_catalog_database.evidence.name

  query = <<-SQL
    SELECT
      requirement,
      COUNT_IF(f.compliance.status = 'PASSED')  AS passed,
      COUNT_IF(f.compliance.status = 'FAILED')  AS failed,
      COUNT(*)                                  AS evaluated
    FROM ${aws_glue_catalog_database.evidence.name}.security_hub_findings
    CROSS JOIN UNNEST(detail.findings) AS t(f)
    CROSS JOIN UNNEST(f.compliance.relatedrequirements) AS r(requirement)
    WHERE year = '2026'
      AND f.recordstate = 'ACTIVE'
    GROUP BY requirement
    ORDER BY failed DESC
  SQL
}
