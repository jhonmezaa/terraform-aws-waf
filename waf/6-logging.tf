# =============================================================================
# WAF Logging Configuration
# =============================================================================
# Configures logging for the WAF Web ACL.
# Log destination can be CloudWatch Logs, S3 bucket, or Kinesis Data Firehose.
#
# IMPORTANT: The log destination must have a name starting with "aws-waf-logs-".
# For CloudFront, create the Firehose in us-east-1.
# =============================================================================

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = var.create && length(var.log_destination_configs) > 0 ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this[0].arn
  log_destination_configs = var.log_destination_configs

  dynamic "redacted_fields" {
    for_each = var.redacted_fields

    content {
      dynamic "method" {
        for_each = lookup(redacted_fields.value, "method", false) ? [true] : []
        content {}
      }

      dynamic "query_string" {
        for_each = lookup(redacted_fields.value, "query_string", false) ? [true] : []
        content {}
      }

      dynamic "uri_path" {
        for_each = lookup(redacted_fields.value, "uri_path", false) ? [true] : []
        content {}
      }

      dynamic "single_header" {
        for_each = lookup(redacted_fields.value, "single_header", null) != null ? toset(redacted_fields.value.single_header) : []
        content {
          name = single_header.value
        }
      }
    }
  }

  dynamic "logging_filter" {
    for_each = var.logging_filter != null ? [true] : []

    content {
      default_behavior = var.logging_filter.default_behavior

      dynamic "filter" {
        for_each = var.logging_filter.filter

        content {
          behavior    = filter.value.behavior
          requirement = filter.value.requirement

          dynamic "condition" {
            for_each = filter.value.condition

            content {
              dynamic "action_condition" {
                for_each = lookup(condition.value, "action_condition", null) != null ? [true] : []
                content {
                  action = condition.value.action_condition.action
                }
              }
              dynamic "label_name_condition" {
                for_each = lookup(condition.value, "label_name_condition", null) != null ? [true] : []
                content {
                  label_name = condition.value.label_name_condition.label_name
                }
              }
            }
          }
        }
      }
    }
  }
}
