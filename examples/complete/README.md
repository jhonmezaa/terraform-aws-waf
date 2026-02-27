# Complete WAF Example

This example demonstrates all features of the WAF module:

## Features Demonstrated

- **IP Sets**: Whitelist (trusted IPs), Blacklist (blocked IPs), and IPv6 trusted addresses
- **Regex Pattern Sets**: Bad bot user agent detection
- **Custom Rule Groups**: Application-specific rules (admin path blocking, body size limits)
- **Web ACL with multiple rule types**:
  - IP-based allow/block lists (priorities 1-2)
  - Geo-blocking by country (priority 5)
  - AWS Managed Rules: Common, Known Bad Inputs, SQLi, Linux (priorities 10-30)
  - Regex-based bot blocking (priority 40)
  - Custom rule group reference (priority 50)
  - Rate limiting at 2000 req/5min (priority 60)
  - URI path traversal blocking (priority 70)
- **Custom response bodies**: JSON error responses for blocked and rate-limited requests
- **Logging to CloudWatch**: With field redaction and filtering
- **Cross-resource references**: Using `ip_set_key`, `regex_set_key`, and `rule_group_key`

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

## Resources Created

| Resource | Count | Description |
|----------|-------|-------------|
| `aws_wafv2_web_acl` | 1 | Web ACL with 10 rules |
| `aws_wafv2_ip_set` | 3 | IPv4 whitelist, IPv4 blacklist, IPv6 trusted |
| `aws_wafv2_regex_pattern_set` | 1 | Bad bot patterns |
| `aws_wafv2_rule_group` | 1 | Custom application rules |
| `aws_wafv2_web_acl_logging_configuration` | 1 | CloudWatch logging |
| `aws_cloudwatch_log_group` | 1 | WAF log storage |

## Naming Convention

Resources follow the pattern: `{region_prefix}-waf-{resource_type}-{account_name}-{project_name}-{key}`

Examples:
- Web ACL: `ause1-waf-prod-myapp-main`
- IP Set: `ause1-waf-prod-myapp-ipset-whitelist`
- Rule Group: `ause1-waf-prod-myapp-rg-custom-rules`

## To Add ALB Association

Uncomment or add the following to associate the WAF with an ALB:

```hcl
module "waf" {
  # ... existing config ...

  associations = {
    alb = {
      web_acl_key  = "main"
      resource_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188"
    }
  }
}
```
