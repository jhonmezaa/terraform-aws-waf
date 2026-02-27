# =============================================================================
# Basic WAF Example
# =============================================================================
# This example creates a simple WAF Web ACL with:
# - AWS Managed Rules (Common Rule Set and Known Bad Inputs)
# - Rate-based rule to prevent DDoS
# - Association placeholder for ALB

module "waf" {
  source = "../../waf"

  account_name = var.account_name
  project_name = var.project_name

  web_acls = {
    main = {
      scope          = "REGIONAL"
      description    = "Basic WAF for ALB protection"
      default_action = "allow"

      rules = [
        # AWS Managed Rules - Common Rule Set
        {
          name            = "aws-common-rules"
          priority        = 10
          override_action = "none"

          managed_rule_group_statement = {
            vendor_name = "AWS"
            name        = "AWSManagedRulesCommonRuleSet"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "aws-common-rules"
            sampled_requests_enabled   = true
          }
        },

        # AWS Managed Rules - Known Bad Inputs
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

        # Rate-based rule - limit 2000 requests per 5 minutes per IP
        {
          name     = "rate-limit"
          priority = 30
          action   = "block"

          rate_based_statement = {
            limit              = 2000
            aggregate_key_type = "IP"
          }

          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "rate-limit"
            sampled_requests_enabled   = true
          }
        }
      ]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "basic-waf-acl"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = {
    Environment = "production"
    Example     = "basic"
  }
}
