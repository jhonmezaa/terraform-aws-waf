output "web_acl_id" {
  description = "The ID of the WAF WebACL."
  value       = module.waf.web_acl_id
}

output "web_acl_arn" {
  description = "The ARN of the WAF WebACL."
  value       = module.waf.web_acl_arn
}

output "web_acl_capacity" {
  description = "The web ACL capacity units (WCUs) currently being used."
  value       = module.waf.web_acl_capacity
}

output "ip_set_arns" {
  description = "Map of IP set names to their ARNs."
  value       = module.waf.ip_set_arns
}

output "standalone_ip_set_arns" {
  description = "Map of standalone IP set names to their ARNs."
  value       = module.waf.standalone_ip_set_arns
}

output "regex_pattern_set_arns" {
  description = "Map of regex pattern set names to their ARNs."
  value       = module.waf.regex_pattern_set_arns
}
