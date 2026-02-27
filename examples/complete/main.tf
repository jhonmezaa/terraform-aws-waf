# =============================================================================
# Complete WAF Example
# =============================================================================
# This example demonstrates all WAF features:
# - IP sets (whitelist + blacklist)
# - Regex pattern set
# - Custom rule group
# - Web ACL with managed rules, IP rate limiting, geo blocking, custom rules
# - Logging to CloudWatch
# - Association with ALB (placeholder)

# -----------------------------------------------------------------------------
# CloudWatch Log Group for WAF Logs
# -----------------------------------------------------------------------------
# The log group name MUST start with "aws-waf-logs-"
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.account_name}-${var.project_name}"
  retention_in_days = 30

  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# -----------------------------------------------------------------------------
# WAF Module
# -----------------------------------------------------------------------------

module "waf" {
  source = "../../waf"

  account_name = var.account_name
  project_name = var.project_name

  # ===========================================================================
  # IP Sets
  # ===========================================================================

  ip_sets = {
    whitelist = {
      scope              = "REGIONAL"
      description        = "Trusted IP addresses"
      ip_address_version = "IPV4"
      addresses = [
        "10.0.0.0/8",
        "172.16.0.0/12",
      ]
    }

    blacklist = {
      scope              = "REGIONAL"
      description        = "Blocked IP addresses"
      ip_address_version = "IPV4"
      addresses = [
        "192.0.2.0/24",
        "198.51.100.0/24",
      ]
    }

    ipv6-trusted = {
      scope              = "REGIONAL"
      description        = "Trusted IPv6 addresses"
      ip_address_version = "IPV6"
      addresses = [
        "2001:db8::/32",
      ]
    }
  }

  # ===========================================================================
  # Regex Pattern Sets
  # ===========================================================================

  regex_pattern_sets = {
    bad-bots = {
      scope       = "REGIONAL"
      description = "Known bad bot user agents"
      regular_expression = [
        "(?i).*scrapy.*",
        "(?i).*bot.*attack.*",
        "(?i).*python-requests.*",
      ]
    }
  }

  # ===========================================================================
  # Custom Rule Groups
  # ===========================================================================

  rule_groups = {
    custom-rules = {
      scope       = "REGIONAL"
      description = "Custom application-specific rules"
      capacity    = 100

      rules = [
        # Block requests to admin paths without proper header
        {
          name     = "block-admin-no-header"
          priority = 1
          action   = "block"

          byte_match_statement = {
            positional_constraint = "STARTS_WITH"
            search_string         = "/admin"
            field_to_match = {
              uri_path = {}
            }
            text_transformation = [
              {
                priority = 0
                type     = "LOWERCASE"
              }
            ]
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-admin-no-header"
            sampled_requests_enabled   = true
          }
        },

        # Block large request bodies (over 8KB)
        {
          name     = "block-large-body"
          priority = 2
          action   = "block"

          size_constraint_statement = {
            comparison_operator = "GT"
            size                = 8192
            field_to_match = {
              body = {}
            }
            text_transformation = [
              {
                priority = 0
                type     = "NONE"
              }
            ]
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-large-body"
            sampled_requests_enabled   = true
          }
        }
      ]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "custom-rule-group"
        sampled_requests_enabled   = true
      }
    }
  }

  # ===========================================================================
  # Web ACL
  # ===========================================================================

  web_acls = {
    main = {
      scope          = "REGIONAL"
      description    = "Complete WAF for production workloads"
      default_action = "allow"

      custom_response_body = {
        blocked = {
          content      = "{\"error\": \"Access Denied\", \"message\": \"Your request has been blocked by WAF.\"}"
          content_type = "APPLICATION_JSON"
        }
        rate-limited = {
          content      = "{\"error\": \"Rate Limited\", \"message\": \"Too many requests. Please try again later.\"}"
          content_type = "APPLICATION_JSON"
        }
      }

      rules = [
        # --- Priority 1: Allow whitelisted IPs ---
        {
          name     = "allow-whitelist"
          priority = 1
          action   = "allow"

          ip_set_reference_statement = {
            ip_set_key = "whitelist"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "allow-whitelist"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 2: Block blacklisted IPs ---
        {
          name     = "block-blacklist"
          priority = 2
          action   = "block"

          ip_set_reference_statement = {
            ip_set_key = "blacklist"
          }

          custom_response = {
            response_code            = 403
            custom_response_body_key = "blocked"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-blacklist"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 5: Geo blocking (block specific countries) ---
        {
          name     = "geo-block"
          priority = 5
          action   = "block"

          geo_match_statement = {
            country_codes = ["CN", "RU", "KP"]
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "geo-block"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 10: AWS Common Rule Set ---
        {
          name            = "aws-common-rules"
          priority        = 10
          override_action = "none"

          managed_rule_group_statement = {
            vendor_name = "AWS"
            name        = "AWSManagedRulesCommonRuleSet"
            rule_action_overrides = [
              {
                name   = "SizeRestrictions_BODY"
                action = "count"
              }
            ]
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "aws-common-rules"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 20: AWS Known Bad Inputs ---
        {
          name            = "aws-known-bad-inputs"
          priority        = 20
          override_action = "none"

          managed_rule_group_statement = {
            vendor_name = "AWS"
            name        = "AWSManagedRulesKnownBadInputsRuleSet"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "aws-known-bad-inputs"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 25: AWS SQL Injection Rules ---
        {
          name            = "aws-sqli-rules"
          priority        = 25
          override_action = "none"

          managed_rule_group_statement = {
            vendor_name = "AWS"
            name        = "AWSManagedRulesSQLiRuleSet"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "aws-sqli-rules"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 30: AWS Linux OS Rules ---
        {
          name            = "aws-linux-rules"
          priority        = 30
          override_action = "none"

          managed_rule_group_statement = {
            vendor_name = "AWS"
            name        = "AWSManagedRulesLinuxRuleSet"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "aws-linux-rules"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 40: Bad bot regex match ---
        {
          name     = "block-bad-bots"
          priority = 40
          action   = "block"

          regex_pattern_set_reference_statement = {
            regex_set_key = "bad-bots"
            field_to_match = {
              single_header = {
                name = "user-agent"
              }
            }
            text_transformation = [
              {
                priority = 0
                type     = "LOWERCASE"
              }
            ]
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-bad-bots"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 50: Custom rule group reference ---
        {
          name            = "custom-rules"
          priority        = 50
          override_action = "none"

          rule_group_reference_statement = {
            rule_group_key = "custom-rules"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "custom-rule-group-ref"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 60: Rate limiting ---
        {
          name     = "rate-limit"
          priority = 60
          action   = "block"

          rate_based_statement = {
            limit              = 2000
            aggregate_key_type = "IP"
          }

          custom_response = {
            response_code            = 429
            custom_response_body_key = "rate-limited"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "rate-limit"
            sampled_requests_enabled   = true
          }
        },

        # --- Priority 70: Block requests with suspicious URI patterns ---
        {
          name     = "block-suspicious-uri"
          priority = 70
          action   = "block"

          byte_match_statement = {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            field_to_match = {
              uri_path = {}
            }
            text_transformation = [
              {
                priority = 0
                type     = "URL_DECODE"
              },
              {
                priority = 1
                type     = "LOWERCASE"
              }
            ]
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-suspicious-uri"
            sampled_requests_enabled   = true
          }
        }
      ]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "complete-waf-acl"
        sampled_requests_enabled   = true
      }
    }
  }

  # ===========================================================================
  # Logging Configuration
  # ===========================================================================

  logging_configurations = {
    main = {
      web_acl_key          = "main"
      log_destination_arns = [aws_cloudwatch_log_group.waf.arn]

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
    }
  }

  tags = {
    Environment = "production"
    Example     = "complete"
  }
}
