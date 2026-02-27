# =============================================================================
# WAFv2 Web ACL Logging Configuration
# =============================================================================
# Log destination ARNs must be prefixed with 'aws-waf-logs-'.
# Supported destinations: CloudWatch Log Group, S3 Bucket, Kinesis Data Firehose.

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  for_each = local.logging_configurations

  resource_arn            = aws_wafv2_web_acl.this[each.value.web_acl_key].arn
  log_destination_configs = each.value.log_destination_arns

  # =========================================================================
  # Redacted Fields
  # =========================================================================

  dynamic "redacted_fields" {
    for_each = each.value.redacted_fields

    content {
      dynamic "method" {
        for_each = redacted_fields.value.method ? [1] : []
        content {}
      }

      dynamic "query_string" {
        for_each = redacted_fields.value.query_string ? [1] : []
        content {}
      }

      dynamic "uri_path" {
        for_each = redacted_fields.value.uri_path ? [1] : []
        content {}
      }

      dynamic "single_header" {
        for_each = redacted_fields.value.single_header != null ? toset(redacted_fields.value.single_header) : []
        content {
          name = single_header.value
        }
      }
    }
  }

  # =========================================================================
  # Logging Filter
  # =========================================================================

  dynamic "logging_filter" {
    for_each = each.value.logging_filter != null ? [each.value.logging_filter] : []

    content {
      default_behavior = logging_filter.value.default_behavior

      dynamic "filter" {
        for_each = logging_filter.value.filter

        content {
          behavior    = filter.value.behavior
          requirement = filter.value.requirement

          dynamic "condition" {
            for_each = filter.value.condition

            content {
              dynamic "action_condition" {
                for_each = condition.value.action_condition != null ? [condition.value.action_condition] : []
                content {
                  action = action_condition.value.action
                }
              }

              dynamic "label_name_condition" {
                for_each = condition.value.label_name_condition != null ? [condition.value.label_name_condition] : []
                content {
                  label_name = label_name_condition.value.label_name
                }
              }
            }
          }
        }
      }
    }
  }
}
