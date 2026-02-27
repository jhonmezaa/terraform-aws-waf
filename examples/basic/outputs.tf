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
