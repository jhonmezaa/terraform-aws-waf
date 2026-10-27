# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1.3] - 2026-10-27

### Fixed

- Replace deprecated `data.aws_region.current.id` with `data.aws_region.current.region` (AWS provider v6) in `waf/8-locals.tf`

## [v1.1.2] - 2026-10-27

### Changed

- Use minimum-only version constraints in the module (`waf/`): AWS provider `~> 6.0` -> `>= 6.0`, so callers are not blocked from newer major provider versions
- Set module `required_version` to `>= 1.3` (was `~> 1.0`): the minimum real Terraform version, since variables use `optional()` object attributes with defaults (Terraform 1.3+)
- Examples (root modules) keep pessimistic constraints: `required_version` `~> 1.3`, AWS provider `~> 6.0`
- Update README requirements table

## [v1.1.1] - 2026-02-28

### Changed

- Documentation only: reformat README tables (no module code changes)

## [v1.1.0] - 2026-02-28

### Added

- `sqli_match_statement` (with `sensitivity_level`) and `xss_match_statement` support in web ACL rules and rule group rules

### Fixed

- Wrap all `rule.value.*` attribute accesses with `try()` so rules declared with `any` type do not fail when optional fields are omitted
- Apply `try()` to nested statement attributes (`managed_rule_group_statement`, `rate_based_statement`, `geo_match_statement`, `ip_set_reference_statement`, `rule_group_reference_statement`)
- Logging `redacted_fields` now emits one block per `single_header` instead of iterating multiple headers in a single block (the AWS API only allows one)

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
