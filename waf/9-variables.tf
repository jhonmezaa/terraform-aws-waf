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
    error_message = "account_name debe tener entre 1 y 32 caracteres."
  }

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.account_name))
    error_message = "account_name solo puede contener letras minúsculas, números y guiones."
  }
}

variable "project_name" {
  description = "Project name for resource naming (e.g., 'myapp', 'api-service')."
  type        = string

  validation {
    condition     = length(var.project_name) > 0 && length(var.project_name) <= 32
    error_message = "project_name debe tener entre 1 y 32 caracteres."
  }

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "project_name solo puede contener letras minúsculas, números y guiones."
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

variable "tags_common" {
  description = "Common tags applied to all resources (naming convention standard)."
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Additional tags to apply to all resources. Kept for backward compatibility; merged after tags_common."
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
    name                            = optional(string)
    scope                           = optional(string, "REGIONAL")
    description                     = optional(string, "Managed by Terraform")
    default_action                  = optional(string, "block")
    default_block_response_code     = optional(number)
    default_block_response_body_key = optional(string)
    default_block_response_headers = optional(list(object({
      name  = string
      value = string
    })), [])
    default_allow_insert_headers = optional(list(object({
      name  = string
      value = string
    })), [])
    token_domains = optional(list(string))

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

    # Data protection: field_type is one of SINGLE_HEADER, SINGLE_COOKIE,
    # SINGLE_QUERY_ARGUMENT, QUERY_STRING, BODY; action is SUBSTITUTION or HASH.
    data_protections = optional(list(object({
      action                     = string
      field_type                 = string
      field_keys                 = optional(list(string))
      exclude_rate_based_details = optional(bool)
      exclude_rule_match_details = optional(bool)
    })), [])
  }))

  default = {}

  validation {
    condition = alltrue([
      for k, v in var.web_acls : contains(["REGIONAL", "CLOUDFRONT"], v.scope)
    ])
    error_message = "El scope del Web ACL debe ser 'REGIONAL' o 'CLOUDFRONT'."
  }

  validation {
    condition = alltrue([
      for k, v in var.web_acls : contains(["allow", "block"], v.default_action)
    ])
    error_message = "default_action del Web ACL debe ser 'allow' o 'block'."
  }

  validation {
    condition = alltrue(flatten([
      for k, v in var.web_acls : [
        for dp in v.data_protections :
        contains(["SUBSTITUTION", "HASH"], dp.action) &&
        contains(["SINGLE_HEADER", "SINGLE_COOKIE", "SINGLE_QUERY_ARGUMENT", "QUERY_STRING", "BODY"], dp.field_type)
      ]
    ]))
    error_message = "data_protections: action debe ser 'SUBSTITUTION' o 'HASH' y field_type uno de SINGLE_HEADER, SINGLE_COOKIE, SINGLE_QUERY_ARGUMENT, QUERY_STRING, BODY."
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
    name               = optional(string)
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
    error_message = "El scope del IP set debe ser 'REGIONAL' o 'CLOUDFRONT'."
  }

  validation {
    condition = alltrue([
      for k, v in var.ip_sets : contains(["IPV4", "IPV6"], v.ip_address_version)
    ])
    error_message = "ip_address_version del IP set debe ser 'IPV4' o 'IPV6'."
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
    name               = optional(string)
    scope              = optional(string, "REGIONAL")
    description        = optional(string, "Managed by Terraform")
    regular_expression = list(string)
  }))

  default = {}

  validation {
    condition = alltrue([
      for k, v in var.regex_pattern_sets : contains(["REGIONAL", "CLOUDFRONT"], v.scope)
    ])
    error_message = "El scope del regex pattern set debe ser 'REGIONAL' o 'CLOUDFRONT'."
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
    name        = optional(string)
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

  validation {
    condition = alltrue([
      for k, v in var.rule_groups : contains(["REGIONAL", "CLOUDFRONT"], v.scope)
    ])
    error_message = "El scope del rule group debe ser 'REGIONAL' o 'CLOUDFRONT'."
  }

  validation {
    condition = alltrue([
      for k, v in var.rule_groups : v.capacity >= 1
    ])
    error_message = "capacity del rule group debe ser mayor o igual a 1."
  }
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

  validation {
    condition = alltrue([
      for k, v in var.logging_configurations :
      length(v.log_destination_arns) >= 1 && length(v.log_destination_arns) <= 8 && alltrue([for arn in v.log_destination_arns : length(regexall("aws-waf-logs-", arn)) > 0])
    ])
    error_message = "Cada logging configuration necesita entre 1 y 8 destinos y cada ARN debe referenciar un recurso cuyo nombre empiece por 'aws-waf-logs-'."
  }

  validation {
    condition = alltrue([
      for k, v in var.logging_configurations :
      v.logging_filter == null ? true : (
        contains(["KEEP", "DROP"], v.logging_filter.default_behavior) &&
        alltrue([
          for f in v.logging_filter.filter :
          contains(["KEEP", "DROP"], f.behavior) && contains(["MEETS_ALL", "MEETS_ANY"], f.requirement) && length(f.condition) >= 1
        ])
      )
    ])
    error_message = "logging_filter: default_behavior y behavior deben ser 'KEEP' o 'DROP', requirement 'MEETS_ALL' o 'MEETS_ANY', y cada filtro necesita al menos una condición."
  }
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
