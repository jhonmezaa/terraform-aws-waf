# Changelog

## [v1.0.0] - 2026-02-27

### Added
- Initial release
- WAF Web ACL with REGIONAL and CLOUDFRONT scope support
- AWS Managed Rule Groups with action overrides and scope down statements
- Managed rule group configs (Bot Control, ATP, ACFP, Anti-DDoS)
- Custom rules: byte match, geo match, geo allowlist, regex match, size constraint, SQLi, XSS
- Rate-based rules with custom keys, scope down statements, and custom responses
- Rule group reference statements with action overrides
- Regex pattern set reference statements
- IP Sets (inline from rules and standalone)
- Regex Pattern Sets
- Resource association (ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access)
- Logging configuration (CloudWatch Logs, S3, Kinesis Data Firehose) with filtering and field redaction
- Custom response bodies for block actions
- Token domains support
- `use_region_prefix` variable for flexible naming
- Full visibility config (CloudWatch metrics) for each rule
- CAPTCHA config support for rules
- Rule labels support
- Basic and advanced examples
