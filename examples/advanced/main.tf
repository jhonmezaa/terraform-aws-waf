# =============================================================================
# Advanced WAF Example
# =============================================================================
# This example creates a WAF Web ACL with:
# - Multiple AWS Managed Rule Groups with action overrides
# - Rate-based rules with custom response
# - Byte match rules
# - Geo match and geo allowlist rules
# - IP set reference rules (inline IP set)
# - Size constraint rules
# - SQLi and XSS match rules
# - Regex match rules
# - Custom response bodies
# - Logging configuration with CloudWatch Logs
# =============================================================================

# CloudWatch Log Group for WAF logs
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.account_name}-${var.project_name}"
  retention_in_days = 30
}

module "waf" {
  source = "../../waf"

  account_name = var.account_name
  project_name = var.project_name

  description    = "Advanced WAF for ${var.project_name}"
  scope          = "REGIONAL"
  default_action = "allow"

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "waf-${var.account_name}-${var.project_name}"
    sampled_requests_enabled   = true
  }

  # Custom response bodies
  custom_response_body = {
    rate_limit_exceeded = {
      content      = "{\"error\": \"Rate limit exceeded\", \"message\": \"Too many requests. Please try again later.\"}"
      content_type = "APPLICATION_JSON"
    }
    blocked_request = {
      content      = "{\"error\": \"Forbidden\", \"message\": \"Your request has been blocked.\"}"
      content_type = "APPLICATION_JSON"
    }
  }

  # =========================================================================
  # AWS Managed Rule Groups
  # =========================================================================

  managed_rule_group_statement_rules = [
    {
      name     = "AWS-AWSManagedRulesCommonRuleSet"
      priority = 10

      statement = {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesCommonRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
      priority = 20

      statement = {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesAmazonIpReputationList"
      priority = 30

      statement = {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAmazonIpReputationList"
      }
    },
    {
      name     = "AWS-AWSManagedRulesBotControlRuleSet"
      priority = 40

      statement = {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"

        rule_action_override = {
          CategoryHttpLibrary = {
            action = "block"
            custom_response = {
              response_code = "404"
            }
          }
          SignalNonBrowserUserAgent = {
            action = "count"
          }
        }

        managed_rule_group_configs = [
          {
            aws_managed_rules_bot_control_rule_set = {
              inspection_level = "COMMON"
            }
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesBotControlRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesAdminProtectionRuleSet"
      priority = 50

      statement = {
        name        = "AWSManagedRulesAdminProtectionRuleSet"
        vendor_name = "AWS"

        # Scope down: only apply to /admin paths
        scope_down_statement = {
          byte_match_statement = {
            positional_constraint = "STARTS_WITH"
            search_string         = "/admin"
            field_to_match = {
              uri_path = true
            }
            text_transformation = [
              {
                priority = 0
                type     = "NONE"
              }
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAdminProtectionRuleSet"
      }
    }
  ]

  # =========================================================================
  # Rate-Based Rules
  # =========================================================================

  rate_based_statement_rules = [
    {
      name     = "rate-limit-api"
      priority = 60
      action   = "block"

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header = {
          name  = "Retry-After"
          value = "300"
        }
      }

      statement = {
        limit                 = 1000
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300

        scope_down_statement = {
          byte_match_statement = {
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/"
            field_to_match = {
              uri_path = true
            }
            text_transformation = [
              {
                priority = 0
                type     = "NONE"
              }
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "rate-limit-api"
      }
    }
  ]

  # =========================================================================
  # Byte Match Rules
  # =========================================================================

  byte_match_statement_rules = [
    {
      name     = "allow-health-check"
      priority = 1
      action   = "allow"

      statement = {
        positional_constraint = "EXACTLY"
        search_string         = "/health"

        text_transformation = [
          {
            priority = 0
            type     = "NONE"
          }
        ]

        field_to_match = {
          uri_path = {}
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "allow-health-check"
      }
    }
  ]

  # =========================================================================
  # Geo Match Rules
  # =========================================================================

  geo_match_statement_rules = [
    {
      name     = "block-sanctioned-countries"
      priority = 70
      action   = "block"

      statement = {
        country_codes = ["KP", "IR", "SY", "CU"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "block-sanctioned-countries"
      }
    }
  ]

  # =========================================================================
  # Geo Allowlist Rules
  # =========================================================================

  geo_allowlist_statement_rules = [
    {
      name     = "allow-only-us-eu"
      priority = 80
      action   = "block"

      statement = {
        country_codes = ["US", "GB", "DE", "FR", "NL", "IE"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "allow-only-us-eu"
      }
    }
  ]

  # =========================================================================
  # IP Set Reference Rules (inline IP set)
  # =========================================================================

  ip_set_reference_statement_rules = [
    {
      name     = "block-bad-ips"
      priority = 5
      action   = "block"

      statement = {
        ip_set = {
          ip_address_version = "IPV4"
          addresses          = ["198.51.100.0/24", "203.0.113.0/24"]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "block-bad-ips"
      }
    }
  ]

  # =========================================================================
  # Size Constraint Rules
  # =========================================================================

  size_constraint_statement_rules = [
    {
      name     = "limit-query-size"
      priority = 90
      action   = "block"

      statement = {
        comparison_operator = "GT"
        size                = 2048

        field_to_match = {
          query_string = {}
        }

        text_transformation = [
          {
            type     = "NONE"
            priority = 0
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "limit-query-size"
      }
    }
  ]

  # =========================================================================
  # SQLi Match Rules
  # =========================================================================

  sqli_match_statement_rules = [
    {
      name     = "sqli-query-string"
      priority = 100
      action   = "block"

      statement = {
        field_to_match = {
          query_string = {}
        }

        text_transformation = [
          {
            type     = "URL_DECODE"
            priority = 1
          },
          {
            type     = "HTML_ENTITY_DECODE"
            priority = 2
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "sqli-query-string"
      }
    }
  ]

  # =========================================================================
  # XSS Match Rules
  # =========================================================================

  xss_match_statement_rules = [
    {
      name     = "xss-uri-path"
      priority = 110
      action   = "block"

      statement = {
        field_to_match = {
          uri_path = {}
        }

        text_transformation = [
          {
            type     = "URL_DECODE"
            priority = 1
          },
          {
            type     = "HTML_ENTITY_DECODE"
            priority = 2
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "xss-uri-path"
      }
    }
  ]

  # =========================================================================
  # Regex Match Rules
  # =========================================================================

  regex_match_statement_rules = [
    {
      name     = "block-admin-paths"
      priority = 120
      action   = "block"

      statement = {
        regex_string = "^/admin|^/wp-admin|^/phpmyadmin"

        text_transformation = [
          {
            priority = 0
            type     = "LOWERCASE"
          }
        ]

        field_to_match = {
          uri_path = {}
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "block-admin-paths"
      }
    }
  ]

  # =========================================================================
  # Standalone IP Sets
  # =========================================================================

  ip_sets = {
    office-ips = {
      ip_address_version = "IPV4"
      addresses          = ["10.0.0.0/8", "172.16.0.0/12"]
      description        = "Office IP ranges"
    }
  }

  # =========================================================================
  # Regex Pattern Sets
  # =========================================================================

  regex_pattern_sets = {
    blocked-paths = {
      description         = "Blocked URL patterns"
      regular_expressions = ["^/admin.*", "^/wp-.*", "^/phpmyadmin.*"]
    }
  }

  # =========================================================================
  # Logging
  # =========================================================================

  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_fields = [
    {
      single_header = ["authorization", "cookie"]
    }
  ]

  logging_filter = {
    default_behavior = "KEEP"
    filter = [
      {
        behavior    = "DROP"
        requirement = "MEETS_ALL"
        condition = [
          {
            action_condition = {
              action = "ALLOW"
            }
          }
        ]
      }
    ]
  }

  tags = {
    Environment = var.account_name
    Project     = var.project_name
  }
}
