# Basic WAF Example

This example demonstrates a minimal WAF configuration with:

- **AWS Managed Rules**: Common Rule Set and Known Bad Inputs for baseline protection
- **Rate-based rule**: Limits requests to 2000 per 5 minutes per IP address
- **REGIONAL scope**: Suitable for ALB, API Gateway, and other regional resources

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

## Resources Created

| Resource | Description |
|----------|-------------|
| `aws_wafv2_web_acl` | Web ACL with managed rules and rate limiting |

## Naming Convention

Resources follow the pattern: `{region_prefix}-waf-{account_name}-{project_name}-{key}`

Example: `ause1-waf-prod-myapp-main`
