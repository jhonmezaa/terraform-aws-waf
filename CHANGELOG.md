# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-27

### Added

- **Web ACL** (`aws_wafv2_web_acl`) with `for_each` pattern
  - REGIONAL and CLOUDFRONT scope support
  - Configurable default action (allow/block) with custom response
  - Custom response bodies (JSON, HTML, plain text)
  - Token domains configuration
  - Association config for request body inspection limits
  - ACL-level captcha and challenge configuration
- **All rule statement types**:
  - `managed_rule_group_statement` with rule action overrides, managed rule group configs (Bot Control, ATP, ACFP), scope-down statements, and version pinning
  - `ip_set_reference_statement` with cross-reference via `ip_set_key` and forwarded IP config
  - `rate_based_statement` with scope-down, forwarded IP, custom keys (IP, header, query string, URI path, cookie), and configurable evaluation window
  - `byte_match_statement` with all field_to_match types (URI path, headers, body, JSON body, cookies, query string, method, single header, single query argument, all query arguments)
  - `size_constraint_statement` with all comparison operators
  - `geo_match_statement` with country codes and forwarded IP config
  - `regex_pattern_set_reference_statement` with cross-reference via `regex_set_key`
  - `rule_group_reference_statement` with cross-reference via `rule_group_key` and rule action overrides
  - `label_match_statement` for label-based rule chaining
  - `and_statement`, `or_statement`, `not_statement` for rule composition (up to 2 levels deep)
- **IP Sets** (`aws_wafv2_ip_set`) for IPv4 and IPv6 addresses
- **Regex Pattern Sets** (`aws_wafv2_regex_pattern_set`) with multiple patterns
- **Custom Rule Groups** (`aws_wafv2_rule_group`) with configurable capacity and custom response bodies
- **Logging Configuration** (`aws_wafv2_web_acl_logging_configuration`)
  - CloudWatch Logs, S3, and Kinesis Firehose destinations
  - Field redaction (method, query string, URI path, single headers)
  - Logging filters with action and label name conditions
- **Web ACL Association** (`aws_wafv2_web_acl_association`) for ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access
- **Cross-resource references** using `_key` pattern (`ip_set_key`, `regex_set_key`, `rule_group_key`, `web_acl_key`)
- **29-region prefix map** with `use_region_prefix` toggle
- **Standard naming convention**: `{region_prefix}-waf-{account_name}-{project_name}-{key}`
- **Input validation** for account_name, project_name, scope, ip_address_version, and default_action
- **Examples**: Basic (managed rules + rate limiting) and Complete (all features)
- **Per-rule captcha and challenge configuration**
- **Rule labels** for label-based rule chaining across rules
- **Custom response headers** for block actions
