# =============================================================================
# Web ACL Outputs
# =============================================================================

output "web_acl_ids" {
  description = "Map of Web ACL keys to their IDs."
  value = {
    for k, v in aws_wafv2_web_acl.this : k => v.id
  }
}

output "web_acl_arns" {
  description = "Map of Web ACL keys to their ARNs."
  value = {
    for k, v in aws_wafv2_web_acl.this : k => v.arn
  }
}

output "web_acl_capacity" {
  description = "Map of Web ACL keys to their capacity units (WCUs)."
  value = {
    for k, v in aws_wafv2_web_acl.this : k => v.capacity
  }
}

output "web_acl_names" {
  description = "Map of Web ACL keys to their names."
  value = {
    for k, v in aws_wafv2_web_acl.this : k => v.name
  }
}

# =============================================================================
# IP Set Outputs
# =============================================================================

output "ip_set_ids" {
  description = "Map of IP Set keys to their IDs."
  value = {
    for k, v in aws_wafv2_ip_set.this : k => v.id
  }
}

output "ip_set_arns" {
  description = "Map of IP Set keys to their ARNs."
  value = {
    for k, v in aws_wafv2_ip_set.this : k => v.arn
  }
}

# =============================================================================
# Regex Pattern Set Outputs
# =============================================================================

output "regex_pattern_set_ids" {
  description = "Map of Regex Pattern Set keys to their IDs."
  value = {
    for k, v in aws_wafv2_regex_pattern_set.this : k => v.id
  }
}

output "regex_pattern_set_arns" {
  description = "Map of Regex Pattern Set keys to their ARNs."
  value = {
    for k, v in aws_wafv2_regex_pattern_set.this : k => v.arn
  }
}

# =============================================================================
# Rule Group Outputs
# =============================================================================

output "rule_group_ids" {
  description = "Map of Rule Group keys to their IDs."
  value = {
    for k, v in aws_wafv2_rule_group.this : k => v.id
  }
}

output "rule_group_arns" {
  description = "Map of Rule Group keys to their ARNs."
  value = {
    for k, v in aws_wafv2_rule_group.this : k => v.arn
  }
}

output "rule_group_capacity" {
  description = "Map of Rule Group keys to their capacity units (WCUs)."
  value = {
    for k, v in aws_wafv2_rule_group.this : k => v.capacity
  }
}

# =============================================================================
# Logging Configuration Outputs
# =============================================================================

output "logging_configuration_ids" {
  description = "Map of Logging Configuration keys to their IDs."
  value = {
    for k, v in aws_wafv2_web_acl_logging_configuration.this : k => v.id
  }
}

# =============================================================================
# Association Outputs
# =============================================================================

output "association_ids" {
  description = "Map of Association keys to their IDs."
  value = {
    for k, v in aws_wafv2_web_acl_association.this : k => v.id
  }
}
