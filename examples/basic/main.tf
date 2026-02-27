# =============================================================================
# Basic WAF Example
# =============================================================================
# This example creates a WAF Web ACL with:
# - AWS Managed Rules (Common, Known Bad Inputs, IP Reputation)
# - A rate-based rule to limit requests
# - Default block action
# =============================================================================

module "waf" {
  source = "../../waf"

  account_name = var.account_name
  project_name = var.project_name

  description    = "Basic WAF for ${var.project_name}"
  scope          = "REGIONAL"
  default_action = "allow"

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "waf-${var.account_name}-${var.project_name}"
    sampled_requests_enabled   = true
  }

  # AWS Managed Rule Groups
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
    }
  ]

  # Rate-based rule: limit to 2000 requests per 5 minutes per IP
  rate_based_statement_rules = [
    {
      name     = "rate-limit-global"
      priority = 50
      action   = "block"

      statement = {
        limit              = 2000
        aggregate_key_type = "IP"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "rate-limit-global"
      }
    }
  ]

  tags = {
    Environment = var.account_name
    Project     = var.project_name
  }
}
