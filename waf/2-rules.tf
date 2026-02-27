# =============================================================================
# Additional WAF Rules (Rate-Based, Regex, Size, SQLi, XSS)
# =============================================================================
# These rules are added to the aws_wafv2_web_acl resource via dynamic blocks.
# They are defined separately for maintainability but are part of the same
# aws_wafv2_web_acl.this resource in 1-waf.tf.
#
# IMPORTANT: Due to Terraform's limitation of not allowing dynamic blocks
# across multiple files for the same resource, the rate_based, regex_match,
# regex_pattern_set_reference, size_constraint, sqli_match, and xss_match
# rules are implemented as additional dynamic rule blocks within the
# aws_wafv2_web_acl.this resource in 1-waf.tf.
#
# This file documents the rule types and their processing logic.
# The actual dynamic blocks are in 1-waf.tf.
# =============================================================================

# NOTE: All rule type processing is handled in 8-locals.tf
# The following rule types are supported:
#
# 1. byte_match_statement_rules    - String match search rules
# 2. geo_allowlist_statement_rules - Country allowlist rules (NOT geo_match)
# 3. geo_match_statement_rules     - Country match rules
# 4. ip_set_reference_statement_rules - IP set reference rules
# 5. managed_rule_group_statement_rules - AWS managed rule groups
# 6. rate_based_statement_rules    - Rate limiting rules
# 7. rule_group_reference_statement_rules - Custom rule group references
# 8. regex_pattern_set_reference_statement_rules - Regex pattern set rules
# 9. regex_match_statement_rules   - Inline regex match rules
# 10. size_constraint_statement_rules - Request size rules
# 11. sqli_match_statement_rules   - SQL injection detection rules
# 12. xss_match_statement_rules    - Cross-site scripting detection rules
