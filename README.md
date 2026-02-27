# terraform-aws-waf

Terraform module for AWS WAF v2 Web ACL with managed rules, custom rules, rate-based rules, IP sets, regex pattern sets, resource associations, and logging configuration.

## Features

- **WAF Web ACL** with REGIONAL and CLOUDFRONT scope support
- **AWS Managed Rule Groups** with action overrides, scope down statements, and advanced configurations (Bot Control, ATP, ACFP, Anti-DDoS)
- **Custom Rules**: byte match, geo match, geo allowlist, IP set reference, regex match, regex pattern set reference, size constraint, SQLi match, XSS match
- **Rate-Based Rules** with configurable limits, custom keys, scope down statements, and custom responses
- **Rule Group References** with action overrides
- **IP Sets** (inline from rules and standalone)
- **Regex Pattern Sets**
- **Resource Association** for ALB, API Gateway, AppSync, Cognito User Pool, App Runner, and Verified Access
- **Logging Configuration** to CloudWatch Logs, S3, or Kinesis Data Firehose with field redaction and log filtering
- **Custom Response Bodies** for block actions
- **Consistent Naming** with region prefix convention

## Usage

### Basic Example

```hcl
module "waf" {
  source = "jhonmezaa/waf/aws//waf"

  account_name = "prod"
  project_name = "myapp"

  description    = "WAF for myapp"
  scope          = "REGIONAL"
  default_action = "allow"

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "waf-prod-myapp"
    sampled_requests_enabled   = true
  }

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
    }
  ]

  rate_based_statement_rules = [
    {
      name     = "rate-limit"
      priority = 50
      action   = "block"
      statement = {
        limit              = 2000
        aggregate_key_type = "IP"
      }
      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "rate-limit"
      }
    }
  ]
}
```

### Associate with ALB

```hcl
module "waf" {
  source = "jhonmezaa/waf/aws//waf"
  # ... WAF configuration ...

  association_resource_arns = [
    aws_lb.main.arn
  ]
}
```

### Enable Logging

```hcl
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-myapp"
  retention_in_days = 30
}

module "waf" {
  source = "jhonmezaa/waf/aws//waf"
  # ... WAF configuration ...

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
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `create` | Whether to create WAF resources | `bool` | `true` | no |
| `account_name` | Account name for resource naming | `string` | - | yes |
| `project_name` | Project name for resource naming | `string` | - | yes |
| `region_prefix` | Region prefix for naming (auto-derived if not set) | `string` | `null` | no |
| `use_region_prefix` | Whether to include region prefix in names | `bool` | `true` | no |
| `tags` | Additional tags for all resources | `map(string)` | `{}` | no |
| `description` | Description of the WebACL | `string` | `"Managed by Terraform"` | no |
| `scope` | REGIONAL or CLOUDFRONT | `string` | `"REGIONAL"` | no |
| `default_action` | Default action: allow or block | `string` | `"block"` | no |
| `default_block_response` | HTTP response code for default block | `number` | `null` | no |
| `default_block_custom_response_body_key` | Custom response body key for default block | `string` | `null` | no |
| `token_domains` | Domains for WAF token acceptance | `list(string)` | `null` | no |
| `visibility_config` | CloudWatch metrics and sampling config | `object` | - | yes |
| `custom_response_body` | Custom response bodies map | `map(object)` | `{}` | no |
| `managed_rule_group_statement_rules` | AWS managed rule groups | `list(object)` | `null` | no |
| `rate_based_statement_rules` | Rate-based rules | `list(object)` | `null` | no |
| `byte_match_statement_rules` | Byte match rules | `list(object)` | `null` | no |
| `geo_allowlist_statement_rules` | Geo allowlist rules | `list(object)` | `null` | no |
| `geo_match_statement_rules` | Geo match rules | `list(object)` | `null` | no |
| `ip_set_reference_statement_rules` | IP set reference rules | `list(object)` | `null` | no |
| `rule_group_reference_statement_rules` | Rule group reference rules | `list(object)` | `null` | no |
| `regex_pattern_set_reference_statement_rules` | Regex pattern set reference rules | `list(object)` | `null` | no |
| `regex_match_statement_rules` | Regex match rules | `list(object)` | `null` | no |
| `size_constraint_statement_rules` | Size constraint rules | `list(object)` | `null` | no |
| `sqli_match_statement_rules` | SQLi match rules | `list(object)` | `null` | no |
| `xss_match_statement_rules` | XSS match rules | `list(object)` | `null` | no |
| `ip_sets` | Standalone IP sets to create | `map(object)` | `{}` | no |
| `regex_pattern_sets` | Regex pattern sets to create | `map(object)` | `{}` | no |
| `association_resource_arns` | Resource ARNs to associate with WAF | `list(string)` | `[]` | no |
| `log_destination_configs` | Logging destination ARNs | `list(string)` | `[]` | no |
| `redacted_fields` | Fields to redact from logs | `list(object)` | `[]` | no |
| `logging_filter` | Log filtering configuration | `object` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| `web_acl_id` | The ID of the WAF WebACL |
| `web_acl_arn` | The ARN of the WAF WebACL |
| `web_acl_capacity` | WCUs currently used by this web ACL |
| `web_acl_name` | The name of the WAF WebACL |
| `logging_configuration_id` | The ARN of the logging configuration |
| `ip_set_arns` | Map of inline IP set names to ARNs |
| `standalone_ip_set_arns` | Map of standalone IP set names to ARNs |
| `regex_pattern_set_arns` | Map of regex pattern set names to ARNs |
| `association_ids` | Map of associated resource ARNs to association IDs |

## AWS Managed Rule Groups Reference

| Rule Group Name | Description |
|----------------|-------------|
| `AWSManagedRulesCommonRuleSet` | Core rule set - protection against common threats |
| `AWSManagedRulesAdminProtectionRuleSet` | Admin page protection |
| `AWSManagedRulesKnownBadInputsRuleSet` | Known bad inputs (Log4j, etc.) |
| `AWSManagedRulesSQLiRuleSet` | SQL injection protection |
| `AWSManagedRulesLinuxRuleSet` | Linux-specific vulnerabilities |
| `AWSManagedRulesUnixRuleSet` | POSIX-specific vulnerabilities |
| `AWSManagedRulesWindowsRuleSet` | Windows-specific vulnerabilities |
| `AWSManagedRulesPHPRuleSet` | PHP-specific vulnerabilities |
| `AWSManagedRulesWordPressRuleSet` | WordPress-specific vulnerabilities |
| `AWSManagedRulesAmazonIpReputationList` | Amazon IP reputation list |
| `AWSManagedRulesAnonymousIpList` | Anonymous IP list |
| `AWSManagedRulesBotControlRuleSet` | Bot control (requires managed_rule_group_configs) |
| `AWSManagedRulesATPRuleSet` | Account takeover prevention |
| `AWSManagedRulesACFPRuleSet` | Account creation fraud prevention |
| `AWSManagedRulesAntiDDoSRuleSet` | DDoS protection |

## Naming Convention

Resources follow the standard naming convention:

```
{region_prefix}-waf-{account_name}-{project_name}
```

Examples:
- WAF: `ause1-waf-prod-myapp`
- IP Set: `ause1-waf-ipset-prod-myapp-blocklist`
- Regex Set: `ause1-waf-regex-prod-myapp-patterns`

## Examples

- [Basic](./examples/basic/) - WAF with managed rules and rate limiting
- [Advanced](./examples/advanced/) - Full-featured WAF with all rule types, logging, and associations

## Requirements

| Name | Version |
|------|---------|
| Terraform | ~> 1.0 |
| AWS Provider | ~> 6.0 |

## License

MIT License - see [LICENSE](LICENSE) for details.
