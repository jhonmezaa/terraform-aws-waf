# terraform-aws-waf

Production-ready Terraform module for AWS WAFv2. Supports Web ACLs, IP Sets, Regex Pattern Sets, Custom Rule Groups, Logging, and Resource Associations with all rule statement types.

## Features

- **Web ACLs** with REGIONAL and CLOUDFRONT scope
- **All rule statement types**: managed rules, IP set, rate-based, byte match, size constraint, geo match, regex, rule group reference, label match
- **Rule composition**: AND, OR, NOT statements for complex rule logic
- **IP Sets** for IPv4 and IPv6 with cross-reference support
- **Regex Pattern Sets** with cross-reference support
- **Custom Rule Groups** with configurable WCU capacity
- **Logging** to CloudWatch, S3, or Kinesis Firehose with field redaction and filtering
- **Associations** for ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access
- **Cross-resource references** via `ip_set_key`, `regex_set_key`, `rule_group_key`, `web_acl_key`
- **29-region prefix map** with configurable naming
- **for_each on all resources** (no count)

## Usage

### Basic - Managed Rules with Rate Limiting

```hcl
module "waf" {
  source = "./terraform-aws-waf/waf"

  account_name = "prod"
  project_name = "myapp"

  web_acls = {
    main = {
      scope          = "REGIONAL"
      default_action = "allow"

      rules = [
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
        {
          name     = "rate-limit"
          priority = 20
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
        metric_name                = "waf-acl"
        sampled_requests_enabled   = true
      }
    }
  }
}
```

### Complete - All Features

```hcl
module "waf" {
  source = "./terraform-aws-waf/waf"

  account_name = "prod"
  project_name = "myapp"

  # IP Sets with cross-reference
  ip_sets = {
    whitelist = {
      ip_address_version = "IPV4"
      addresses          = ["10.0.0.0/8"]
    }
    blacklist = {
      ip_address_version = "IPV4"
      addresses          = ["192.0.2.0/24"]
    }
  }

  # Regex Pattern Sets
  regex_pattern_sets = {
    bad-bots = {
      regular_expression = ["(?i).*scrapy.*", "(?i).*bot.*attack.*"]
    }
  }

  # Custom Rule Groups
  rule_groups = {
    custom = {
      capacity = 100
      rules = [
        {
          name     = "block-admin"
          priority = 1
          action   = "block"
          byte_match_statement = {
            positional_constraint = "STARTS_WITH"
            search_string         = "/admin"
            field_to_match        = { uri_path = {} }
            text_transformation   = [{ priority = 0, type = "LOWERCASE" }]
          }
          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-admin"
            sampled_requests_enabled   = true
          }
        }
      ]
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "custom-rg"
        sampled_requests_enabled   = true
      }
    }
  }

  # Web ACL referencing IP sets, regex sets, and rule groups
  web_acls = {
    main = {
      scope          = "REGIONAL"
      default_action = "allow"
      rules = [
        {
          name     = "allow-whitelist"
          priority = 1
          action   = "allow"
          ip_set_reference_statement = { ip_set_key = "whitelist" }
          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "allow-whitelist"
            sampled_requests_enabled   = true
          }
        },
        {
          name     = "block-blacklist"
          priority = 2
          action   = "block"
          ip_set_reference_statement = { ip_set_key = "blacklist" }
          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-blacklist"
            sampled_requests_enabled   = true
          }
        },
        {
          name     = "block-bad-bots"
          priority = 10
          action   = "block"
          regex_pattern_set_reference_statement = {
            regex_set_key  = "bad-bots"
            field_to_match = { single_header = { name = "user-agent" } }
            text_transformation = [{ priority = 0, type = "LOWERCASE" }]
          }
          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "block-bad-bots"
            sampled_requests_enabled   = true
          }
        },
        {
          name            = "custom-rules"
          priority        = 20
          override_action = "none"
          rule_group_reference_statement = { rule_group_key = "custom" }
          visibility_config = {
            cloudwatch_metrics_enabled = true
            metric_name                = "custom-rules"
            sampled_requests_enabled   = true
          }
        }
      ]
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "waf-acl"
        sampled_requests_enabled   = true
      }
    }
  }

  # Logging
  logging_configurations = {
    main = {
      web_acl_key          = "main"
      log_destination_arns = [aws_cloudwatch_log_group.waf.arn]
      redacted_fields      = [{ single_header = ["authorization"] }]
    }
  }

  # Association
  associations = {
    alb = {
      web_acl_key  = "main"
      resource_arn = aws_lb.example.arn
    }
  }
}
```

## Requirements

| Name      | Version |
| --------- | ------- |
| terraform | ~> 1.0  |
| aws       | ~> 6.0  |

## Resources

| Resource                                  | Description                   |
| ----------------------------------------- | ----------------------------- |
| `aws_wafv2_web_acl`                       | WAF Web Access Control List   |
| `aws_wafv2_ip_set`                        | IP address sets for IPv4/IPv6 |
| `aws_wafv2_regex_pattern_set`             | Regex pattern sets            |
| `aws_wafv2_rule_group`                    | Custom rule groups            |
| `aws_wafv2_web_acl_logging_configuration` | Logging configuration         |
| `aws_wafv2_web_acl_association`           | Resource association          |

## Inputs

### General

| Name                | Description                       | Type          | Default | Required |
| ------------------- | --------------------------------- | ------------- | ------- | -------- |
| `create`            | Whether to create WAF resources   | `bool`        | `true`  | no       |
| `account_name`      | Account name for resource naming  | `string`      | -       | yes      |
| `project_name`      | Project name for resource naming  | `string`      | -       | yes      |
| `region_prefix`     | Region prefix override            | `string`      | `null`  | no       |
| `use_region_prefix` | Include region prefix in names    | `bool`        | `true`  | no       |
| `tags`              | Additional tags for all resources | `map(string)` | `{}`    | no       |

### Web ACLs

| Name       | Description                   | Type                 | Default |
| ---------- | ----------------------------- | -------------------- | ------- |
| `web_acls` | Map of Web ACL configurations | `map(object({...}))` | `{}`    |

### IP Sets

| Name      | Description                  | Type                 | Default |
| --------- | ---------------------------- | -------------------- | ------- |
| `ip_sets` | Map of IP Set configurations | `map(object({...}))` | `{}`    |

### Regex Pattern Sets

| Name                 | Description                             | Type                 | Default |
| -------------------- | --------------------------------------- | -------------------- | ------- |
| `regex_pattern_sets` | Map of Regex Pattern Set configurations | `map(object({...}))` | `{}`    |

### Rule Groups

| Name          | Description                      | Type                 | Default |
| ------------- | -------------------------------- | -------------------- | ------- |
| `rule_groups` | Map of Rule Group configurations | `map(object({...}))` | `{}`    |

### Logging

| Name                     | Description                   | Type                 | Default |
| ------------------------ | ----------------------------- | -------------------- | ------- |
| `logging_configurations` | Map of logging configurations | `map(object({...}))` | `{}`    |

### Associations

| Name           | Description                 | Type                 | Default |
| -------------- | --------------------------- | -------------------- | ------- |
| `associations` | Map of Web ACL associations | `map(object({...}))` | `{}`    |

## Outputs

| Name                        | Description                              |
| --------------------------- | ---------------------------------------- |
| `web_acl_ids`               | Map of Web ACL keys to IDs               |
| `web_acl_arns`              | Map of Web ACL keys to ARNs              |
| `web_acl_capacity`          | Map of Web ACL keys to WCU capacity      |
| `web_acl_names`             | Map of Web ACL keys to names             |
| `ip_set_ids`                | Map of IP Set keys to IDs                |
| `ip_set_arns`               | Map of IP Set keys to ARNs               |
| `regex_pattern_set_ids`     | Map of Regex Pattern Set keys to IDs     |
| `regex_pattern_set_arns`    | Map of Regex Pattern Set keys to ARNs    |
| `rule_group_ids`            | Map of Rule Group keys to IDs            |
| `rule_group_arns`           | Map of Rule Group keys to ARNs           |
| `rule_group_capacity`       | Map of Rule Group keys to WCU capacity   |
| `logging_configuration_ids` | Map of Logging Configuration keys to IDs |
| `association_ids`           | Map of Association keys to IDs           |

## Naming Convention

All resources follow the standard naming pattern:

```
{region_prefix}-waf-{resource_type}-{account_name}-{project_name}-{key}
```

| Resource   | Pattern                                        | Example                                |
| ---------- | ---------------------------------------------- | -------------------------------------- |
| Web ACL    | `{prefix}-waf-{account}-{project}-{key}`       | `ause1-waf-prod-myapp-main`            |
| IP Set     | `{prefix}-waf-{account}-{project}-ipset-{key}` | `ause1-waf-prod-myapp-ipset-whitelist` |
| Regex Set  | `{prefix}-waf-{account}-{project}-regex-{key}` | `ause1-waf-prod-myapp-regex-bad-bots`  |
| Rule Group | `{prefix}-waf-{account}-{project}-rg-{key}`    | `ause1-waf-prod-myapp-rg-custom`       |

## Supported Rule Statement Types

| Statement                               | Web ACL | Rule Group | Description                       |
| --------------------------------------- | ------- | ---------- | --------------------------------- |
| `managed_rule_group_statement`          | Yes     | No         | AWS and marketplace managed rules |
| `ip_set_reference_statement`            | Yes     | Yes        | Match against IP sets             |
| `rate_based_statement`                  | Yes     | No         | Rate-limit requests               |
| `byte_match_statement`                  | Yes     | Yes        | Match byte sequences              |
| `size_constraint_statement`             | Yes     | Yes        | Match request sizes               |
| `geo_match_statement`                   | Yes     | Yes        | Match by country                  |
| `regex_pattern_set_reference_statement` | Yes     | Yes        | Match regex patterns              |
| `rule_group_reference_statement`        | Yes     | No         | Reference custom rule groups      |
| `label_match_statement`                 | Yes     | Yes        | Match by labels                   |
| `and_statement`                         | Yes     | No         | Combine with AND                  |
| `or_statement`                          | Yes     | No         | Combine with OR                   |
| `not_statement`                         | Yes     | No         | Negate a statement                |

## Cross-Resource References

Use `_key` parameters to reference resources defined in the same module:

| Parameter        | References                   | Used In                                  |
| ---------------- | ---------------------------- | ---------------------------------------- |
| `ip_set_key`     | `ip_sets` map key            | `ip_set_reference_statement`             |
| `regex_set_key`  | `regex_pattern_sets` map key | `regex_pattern_set_reference_statement`  |
| `rule_group_key` | `rule_groups` map key        | `rule_group_reference_statement`         |
| `web_acl_key`    | `web_acls` map key           | `logging_configurations`, `associations` |

## Examples

- [Basic](examples/basic/) - Managed rules with rate limiting
- [Complete](examples/complete/) - All features: IP sets, regex, rule groups, logging, associations

## AWS Managed Rule Groups

Common AWS managed rule groups:

| Name                                    | Description                       | WCU |
| --------------------------------------- | --------------------------------- | --- |
| `AWSManagedRulesCommonRuleSet`          | Core rules for common threats     | 700 |
| `AWSManagedRulesKnownBadInputsRuleSet`  | Known bad input patterns          | 200 |
| `AWSManagedRulesSQLiRuleSet`            | SQL injection protection          | 200 |
| `AWSManagedRulesLinuxRuleSet`           | Linux-specific exploits           | 200 |
| `AWSManagedRulesUnixRuleSet`            | POSIX OS exploits                 | 100 |
| `AWSManagedRulesWindowsRuleSet`         | Windows-specific exploits         | 200 |
| `AWSManagedRulesPHPRuleSet`             | PHP application exploits          | 100 |
| `AWSManagedRulesWordPressRuleSet`       | WordPress exploits                | 100 |
| `AWSManagedRulesAmazonIpReputationList` | Amazon IP reputation              | 25  |
| `AWSManagedRulesAnonymousIpList`        | Anonymous IP addresses            | 50  |
| `AWSManagedRulesBotControlRuleSet`      | Bot control (requires config)     | 50  |
| `AWSManagedRulesATPRuleSet`             | Account takeover prevention       | 50  |
| `AWSManagedRulesACFPRuleSet`            | Account creation fraud prevention | 50  |

## License

MIT License - see [LICENSE](LICENSE) for details.
