# =============================================================================
# Web ACL Outputs
# =============================================================================

output "web_acl_arns" {
  description = "ARNs of the created Web ACLs."
  value       = module.waf.web_acl_arns
}

output "web_acl_ids" {
  description = "IDs of the created Web ACLs."
  value       = module.waf.web_acl_ids
}

output "web_acl_capacity" {
  description = "Capacity units used by the Web ACLs."
  value       = module.waf.web_acl_capacity
}

# =============================================================================
# IP Set Outputs
# =============================================================================

output "ip_set_arns" {
  description = "ARNs of the created IP Sets."
  value       = module.waf.ip_set_arns
}

# =============================================================================
# Regex Pattern Set Outputs
# =============================================================================

output "regex_pattern_set_arns" {
  description = "ARNs of the created Regex Pattern Sets."
  value       = module.waf.regex_pattern_set_arns
}

# =============================================================================
# Rule Group Outputs
# =============================================================================

output "rule_group_arns" {
  description = "ARNs of the created Rule Groups."
  value       = module.waf.rule_group_arns
}

# =============================================================================
# Logging Outputs
# =============================================================================

output "logging_configuration_ids" {
  description = "IDs of the logging configurations."
  value       = module.waf.logging_configuration_ids
}
