# =============================================================================
# WAF Web ACL Outputs
# =============================================================================

output "web_acl_id" {
  description = "The ID of the WAF WebACL."
  value       = try(aws_wafv2_web_acl.this[0].id, null)
}

output "web_acl_arn" {
  description = "The ARN of the WAF WebACL."
  value       = try(aws_wafv2_web_acl.this[0].arn, null)
}

output "web_acl_capacity" {
  description = "The web ACL capacity units (WCUs) currently being used by this web ACL."
  value       = try(aws_wafv2_web_acl.this[0].capacity, null)
}

output "web_acl_name" {
  description = "The name of the WAF WebACL."
  value       = try(aws_wafv2_web_acl.this[0].name, null)
}

# =============================================================================
# Logging Configuration Outputs
# =============================================================================

output "logging_configuration_id" {
  description = "The ARN of the WAFv2 Web ACL logging configuration."
  value       = try(aws_wafv2_web_acl_logging_configuration.this[0].id, null)
}

# =============================================================================
# IP Set Outputs
# =============================================================================

output "ip_set_arns" {
  description = "Map of IP set names to their ARNs (inline IP sets created from rules)."
  value = {
    for k, v in aws_wafv2_ip_set.this : k => v.arn
  }
}

output "standalone_ip_set_arns" {
  description = "Map of standalone IP set names to their ARNs."
  value = {
    for k, v in aws_wafv2_ip_set.standalone : k => v.arn
  }
}

# =============================================================================
# Regex Pattern Set Outputs
# =============================================================================

output "regex_pattern_set_arns" {
  description = "Map of regex pattern set names to their ARNs."
  value = {
    for k, v in aws_wafv2_regex_pattern_set.this : k => v.arn
  }
}

# =============================================================================
# Association Outputs
# =============================================================================

output "association_ids" {
  description = "Map of associated resource ARNs to their WAF association IDs."
  value = {
    for k, v in aws_wafv2_web_acl_association.this : k => v.id
  }
}
