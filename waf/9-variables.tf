# =============================================================================
# General Configuration Variables
# =============================================================================

variable "create" {
  description = "Whether to create WAF resources."
  type        = bool
  default     = true
}

variable "account_name" {
  description = "Account name for resource naming (e.g., 'prod', 'staging', 'dev')."
  type        = string

  validation {
    condition     = length(var.account_name) > 0 && length(var.account_name) <= 32
    error_message = "account_name must be between 1 and 32 characters."
  }

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.account_name))
    error_message = "account_name can only contain lowercase letters, numbers, and hyphens."
  }
}

variable "project_name" {
  description = "Project name for resource naming (e.g., 'myapp', 'api-service')."
  type        = string

  validation {
    condition     = length(var.project_name) > 0 && length(var.project_name) <= 32
    error_message = "project_name must be between 1 and 32 characters."
  }

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "project_name can only contain lowercase letters, numbers, and hyphens."
  }
}

variable "region_prefix" {
  description = "Region prefix for naming. If not provided, will be derived from current region."
  type        = string
  default     = null
}

variable "use_region_prefix" {
  description = "Whether to include the region prefix in resource names."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}

# =============================================================================
# Web ACL Configuration
# =============================================================================

variable "web_acls" {
  description = <<-EOT
    Map of Web ACL configurations to create.
    Each key becomes part of the resource name: {region_prefix}-waf-{account_name}-{project_name}-{key}
  EOT

  type = map(object({
    scope                           = optional(string, "REGIONAL")
    description                     = optional(string, "Managed by Terraform")
    default_action                  = optional(string, "block")
    default_block_response_code     = optional(number)
    default_block_response_body_key = optional(string)
    token_domains                   = optional(list(string))

    custom_response_body = optional(map(object({
      content      = string
      content_type = string
    })), {})

    # Rules use 'any' type because WAF rules contain heterogeneous statement types
    # (managed_rule_group_statement, ip_set_reference_statement, byte_match_statement, etc.)
    # that cannot be unified in a typed list. Each rule should contain:
    #   name, priority, action/override_action, one statement type, visibility_config
    rules = optional(any, [])

    visibility_config = object({
      cloudwatch_metrics_enabled = bool
      metric_name                = string
      sampled_requests_enabled   = bool
    })

    captcha_config = optional(object({
      immunity_time = number
    }))

    challenge_config = optional(object({
      immunity_time = number
    }))

    association_config = optional(object({
      request_body = optional(map(object({
        default_size_inspection_limit = string
      })))
    }))
  }))

  default = {}

  validation {
    condition = alltrue([
      for k, v in var.web_acls : contains(["REGIONAL", "CLOUDFRONT"], v.scope)
    ])
    error_message = "Web ACL scope must be either 'REGIONAL' or 'CLOUDFRONT'."
  }

  validation {
    condition = alltrue([
      for k, v in var.web_acls : contains(["allow", "block"], v.default_action)
    ])
    error_message = "Web ACL default_action must be either 'allow' or 'block'."
  }
}

# =============================================================================
# IP Set Configuration
# =============================================================================

variable "ip_sets" {
  description = <<-EOT
    Map of IP Set configurations to create.
    Each key becomes part of the resource name: {region_prefix}-waf-{account_name}-{project_name}-ipset-{key}
  EOT

  type = map(object({
    scope              = optional(string, "REGIONAL")
    description        = optional(string, "Managed by Terraform")
    ip_address_version = optional(string, "IPV4")
    addresses          = list(string)
  }))

  default = {}

  validation {
    condition = alltrue([
      for k, v in var.ip_sets : contains(["REGIONAL", "CLOUDFRONT"], v.scope)
    ])
    error_message = "IP set scope must be either 'REGIONAL' or 'CLOUDFRONT'."
  }

  validation {
    condition = alltrue([
      for k, v in var.ip_sets : contains(["IPV4", "IPV6"], v.ip_address_version)
    ])
    error_message = "IP set ip_address_version must be either 'IPV4' or 'IPV6'."
  }
}

# =============================================================================
# Regex Pattern Set Configuration
# =============================================================================

variable "regex_pattern_sets" {
  description = <<-EOT
    Map of Regex Pattern Set configurations to create.
    Each key becomes part of the resource name: {region_prefix}-waf-{account_name}-{project_name}-regex-{key}
  EOT

  type = map(object({
    scope              = optional(string, "REGIONAL")
    description        = optional(string, "Managed by Terraform")
    regular_expression = list(string)
  }))

  default = {}

  validation {
    condition = alltrue([
      for k, v in var.regex_pattern_sets : contains(["REGIONAL", "CLOUDFRONT"], v.scope)
    ])
    error_message = "Regex pattern set scope must be either 'REGIONAL' or 'CLOUDFRONT'."
  }
}

# =============================================================================
# Rule Group Configuration
# =============================================================================

variable "rule_groups" {
  description = <<-EOT
    Map of custom Rule Group configurations to create.
    Each key becomes part of the resource name: {region_prefix}-waf-{account_name}-{project_name}-rg-{key}
  EOT

  type = map(object({
    scope       = optional(string, "REGIONAL")
    description = optional(string, "Managed by Terraform")
    capacity    = number

    custom_response_body = optional(map(object({
      content      = string
      content_type = string
    })), {})

    # Rules use 'any' type for the same reason as web_acls rules
    rules = optional(any, [])

    visibility_config = object({
      cloudwatch_metrics_enabled = bool
      metric_name                = string
      sampled_requests_enabled   = bool
    })
  }))

  default = {}
}

# =============================================================================
# Logging Configuration
# =============================================================================

variable "logging_configurations" {
  description = <<-EOT
    Map of WAF logging configurations.
    Each key is a unique identifier for the logging configuration.
  EOT

  type = map(object({
    web_acl_key          = string
    log_destination_arns = list(string)

    redacted_fields = optional(list(object({
      method        = optional(bool, false)
      query_string  = optional(bool, false)
      uri_path      = optional(bool, false)
      single_header = optional(list(string))
    })), [])

    logging_filter = optional(object({
      default_behavior = string
      filter = list(object({
        behavior    = string
        requirement = string
        condition = list(object({
          action_condition = optional(object({
            action = string
          }))
          label_name_condition = optional(object({
            label_name = string
          }))
        }))
      }))
    }))
  }))

  default = {}
}

# =============================================================================
# Web ACL Association Configuration
# =============================================================================

variable "associations" {
  description = <<-EOT
    Map of Web ACL associations.
    Each key is a unique identifier for the association.
  EOT

  type = map(object({
    web_acl_key  = string
    resource_arn = string
  }))

  default = {}
}
