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
