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

  # Redacted fields: method, query_string, uri_path (one block each)
  dynamic "redacted_fields" {
    for_each = [
      for rf in each.value.redacted_fields : rf
      if rf.method
    ]
    content {
      method {}
    }
  }

  dynamic "redacted_fields" {
    for_each = [
      for rf in each.value.redacted_fields : rf
      if rf.query_string
    ]
    content {
      query_string {}
    }
  }

  dynamic "redacted_fields" {
    for_each = [
      for rf in each.value.redacted_fields : rf
      if rf.uri_path
    ]
    content {
      uri_path {}
    }
  }

  # Redacted fields: single_header (one block per header name)
  dynamic "redacted_fields" {
    for_each = toset(flatten([
      for rf in each.value.redacted_fields : rf.single_header != null ? rf.single_header : []
    ]))
    content {
      single_header {
        name = redacted_fields.value
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
