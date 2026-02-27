# =============================================================================
# General Configuration Variables
# =============================================================================

variable "create" {
  description = "Whether to create WAF resources."
  type        = bool
  default     = true
}

variable "account_name" {
  description = "Account name for resource naming."
  type        = string

  validation {
    condition     = length(var.account_name) > 0 && length(var.account_name) <= 32
    error_message = "account_name must be between 1 and 32 characters."
  }

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.account_name))
    error_message = "account_name can only contain lowercase letters, numbers and hyphens."
  }
}

variable "project_name" {
  description = "Project name for resource naming."
  type        = string

  validation {
    condition     = length(var.project_name) > 0 && length(var.project_name) <= 32
    error_message = "project_name must be between 1 and 32 characters."
  }

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "project_name can only contain lowercase letters, numbers and hyphens."
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
# WAF Web ACL Configuration
# =============================================================================

variable "description" {
  description = "A friendly description of the WebACL."
  type        = string
  default     = "Managed by Terraform"
}

variable "scope" {
  description = "Specifies whether this is for a CloudFront distribution or regional application. Values: CLOUDFRONT, REGIONAL."
  type        = string
  default     = "REGIONAL"
  nullable    = false

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "Allowed values: CLOUDFRONT, REGIONAL."
  }
}

variable "default_action" {
  description = "Specifies the default action for the WebACL. Possible values: allow, block."
  type        = string
  default     = "block"
  nullable    = false

  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "Allowed values: allow, block."
  }
}

variable "default_block_response" {
  description = "HTTP response code for the default block action. Only used when default_action is block."
  type        = number
  default     = null
}

variable "default_block_custom_response_body_key" {
  description = "References a key defined in custom_response_body for the default block action."
  type        = string
  default     = null
}

variable "token_domains" {
  description = "Specifies the domains that AWS WAF should accept in a web request token."
  type        = list(string)
  default     = null
}

variable "visibility_config" {
  description = "Defines and enables Amazon CloudWatch metrics and web request sample collection."
  type = object({
    cloudwatch_metrics_enabled = bool
    metric_name                = string
    sampled_requests_enabled   = bool
  })
  nullable = false
}

variable "custom_response_body" {
  description = "Defines custom response bodies that can be referenced by custom_response actions."
  type = map(object({
    content      = string
    content_type = string
  }))
  default  = {}
  nullable = false
}

# =============================================================================
# Managed Rule Group Statement Rules
# =============================================================================

variable "managed_rule_group_statement_rules" {
  description = "A list of managed rule group statement rules."
  type = list(object({
    name            = string
    priority        = number
    override_action = optional(string)
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    statement = object({
      name                             = string
      vendor_name                      = string
      version                          = optional(string)
      scope_down_not_statement_enabled = optional(bool, false)
      scope_down_statement = optional(object({
        byte_match_statement = object({
          positional_constraint = string
          search_string         = string
          field_to_match = object({
            all_query_arguments   = optional(bool)
            body                  = optional(bool)
            method                = optional(bool)
            query_string          = optional(bool)
            single_header         = optional(object({ name = string }))
            single_query_argument = optional(object({ name = string }))
            uri_path              = optional(bool)
          })
          text_transformation = list(object({
            priority = number
            type     = string
          }))
        })
      }), null)
      rule_action_override = optional(map(object({
        action = string
        custom_request_handling = optional(object({
          insert_header = object({
            name  = string
            value = string
          })
        }), null)
        custom_response = optional(object({
          response_code            = string
          custom_response_body_key = optional(string)
          response_header = optional(object({
            name  = string
            value = string
          }), null)
        }), null)
      })), null)
      managed_rule_group_configs = optional(list(object({
        aws_managed_rules_anti_ddos_rule_set = optional(object({
          sensitivity_to_block = optional(string)
          client_side_action_config = optional(object({
            challenge = object({
              usage_of_action = string
              sensitivity     = optional(string)
              exempt_uri_regular_expression = optional(list(object({
                regex_string = string
              })))
            })
          }))
        }))
        aws_managed_rules_bot_control_rule_set = optional(object({
          inspection_level        = string
          enable_machine_learning = optional(bool, true)
        }), null)
        aws_managed_rules_atp_rule_set = optional(object({
          enable_regex_in_path = optional(bool)
          login_path           = string
          request_inspection = optional(object({
            payload_type = string
            password_field = object({
              identifier = string
            })
            username_field = object({
              identifier = string
            })
          }), null)
          response_inspection = optional(object({
            body_contains = optional(object({
              success_strings = list(string)
              failure_strings = list(string)
            }), null)
            header = optional(object({
              name           = string
              success_values = list(string)
              failure_values = list(string)
            }), null)
            json = optional(object({
              identifier     = string
              success_values = list(string)
              failure_values = list(string)
            }), null)
            status_code = optional(object({
              success_codes = list(string)
              failure_codes = list(string)
            }), null)
          }), null)
        }), null)
        aws_managed_rules_acfp_rule_set = optional(object({
          creation_path          = string
          enable_regex_in_path   = optional(bool)
          registration_page_path = string
          request_inspection = optional(object({
            payload_type = string
            password_field = optional(object({
              identifier = string
            }), null)
            username_field = optional(object({
              identifier = string
            }), null)
            email_field = optional(object({
              identifier = string
            }), null)
            address_fields = optional(object({
              identifiers = list(string)
            }), null)
            phone_number_fields = optional(object({
              identifiers = list(string)
            }), null)
          }), null)
          response_inspection = optional(object({
            body_contains = optional(object({
              success_strings = list(string)
              failure_strings = list(string)
            }), null)
            header = optional(object({
              name           = string
              success_values = list(string)
              failure_values = list(string)
            }), null)
            json = optional(object({
              identifier     = string
              success_values = list(string)
              failure_values = list(string)
            }), null)
            status_code = optional(object({
              success_codes = list(string)
              failure_codes = list(string)
            }), null)
          }), null)
        }))
      })), null)
    })
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Rate Based Statement Rules
# =============================================================================

variable "rate_based_statement_rules" {
  description = "A list of rate-based rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = object({
      limit                 = number
      aggregate_key_type    = string
      evaluation_window_sec = optional(number)
      forwarded_ip_config = optional(object({
        fallback_behavior = string
        header_name       = string
      }), null)
      custom_key = optional(list(object({
        ip = optional(object({}), null)
        header = optional(object({
          name = string
          text_transformation = list(object({
            priority = number
            type     = string
          }))
        }), null)
      })), null)
      scope_down_statement = optional(object({
        byte_match_statement = object({
          positional_constraint = string
          search_string         = string
          field_to_match = object({
            all_query_arguments   = optional(bool)
            body                  = optional(bool)
            method                = optional(bool)
            query_string          = optional(bool)
            single_header         = optional(object({ name = string }))
            single_query_argument = optional(object({ name = string }))
            uri_path              = optional(bool)
          })
          text_transformation = list(object({
            priority = number
            type     = string
          }))
        })
      }), null)
    })
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Byte Match Statement Rules
# =============================================================================

variable "byte_match_statement_rules" {
  description = "A list of byte match statement rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Geo Allowlist Statement Rules
# =============================================================================

variable "geo_allowlist_statement_rules" {
  description = "A list of geo allowlist rules (uses NOT geo_match internally)."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    statement  = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Geo Match Statement Rules
# =============================================================================

variable "geo_match_statement_rules" {
  description = "A list of geo match rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# IP Set Reference Statement Rules
# =============================================================================

variable "ip_set_reference_statement_rules" {
  description = "A list of IP set reference rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Rule Group Reference Statement Rules
# =============================================================================

variable "rule_group_reference_statement_rules" {
  description = "A list of rule group reference rules."
  type = list(object({
    name            = string
    priority        = number
    override_action = optional(string)
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    statement = object({
      arn = string
      rule_action_override = optional(map(object({
        action = string
        custom_request_handling = optional(object({
          insert_header = object({
            name  = string
            value = string
          })
        }), null)
        custom_response = optional(object({
          response_code = string
          response_header = optional(object({
            name  = string
            value = string
          }), null)
        }), null)
      })), null)
    })
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Regex Pattern Set Reference Statement Rules
# =============================================================================

variable "regex_pattern_set_reference_statement_rules" {
  description = "A list of regex pattern set reference rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    statement  = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Regex Match Statement Rules
# =============================================================================

variable "regex_match_statement_rules" {
  description = "A list of regex match rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    statement  = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# Size Constraint Statement Rules
# =============================================================================

variable "size_constraint_statement_rules" {
  description = "A list of size constraint rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# SQLi Match Statement Rules
# =============================================================================

variable "sqli_match_statement_rules" {
  description = "A list of SQL injection match rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# XSS Match Statement Rules
# =============================================================================

variable "xss_match_statement_rules" {
  description = "A list of cross-site scripting match rules."
  type = list(object({
    name     = string
    priority = number
    action   = string
    captcha_config = optional(object({
      immunity_time_property = object({
        immunity_time = number
      })
    }), null)
    rule_label = optional(list(string), null)
    custom_response = optional(object({
      response_code            = string
      custom_response_body_key = optional(string, null)
      response_header = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
    statement = any
    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool)
      metric_name                = string
      sampled_requests_enabled   = optional(bool)
    }), null)
  }))
  default = null
}

# =============================================================================
# IP Sets (Standalone)
# =============================================================================

variable "ip_sets" {
  description = "Map of standalone IP sets to create."
  type = map(object({
    ip_address_version = string
    addresses          = list(string)
    description        = optional(string, "Managed by Terraform")
  }))
  default = {}
}

# =============================================================================
# Regex Pattern Sets
# =============================================================================

variable "regex_pattern_sets" {
  description = "Map of regex pattern sets to create."
  type = map(object({
    description         = optional(string, "Managed by Terraform")
    regular_expressions = list(string)
  }))
  default = {}
}

# =============================================================================
# Association
# =============================================================================

variable "association_resource_arns" {
  description = "List of ARNs of resources to associate with the WAF Web ACL."
  type        = list(string)
  default     = []
}

# =============================================================================
# Logging Configuration
# =============================================================================

variable "log_destination_configs" {
  description = "List of ARNs of the logging destinations. Resource name must start with aws-waf-logs-."
  type        = list(string)
  default     = []
}

variable "redacted_fields" {
  description = "List of fields to redact from the logs."
  type = list(object({
    method        = optional(bool, false)
    query_string  = optional(bool, false)
    uri_path      = optional(bool, false)
    single_header = optional(list(string), null)
  }))
  default = []
}

variable "logging_filter" {
  description = "Filtering configuration for WAF logs."
  type = object({
    default_behavior = string
    filter = list(object({
      behavior    = string
      requirement = string
      condition = list(object({
        action_condition = optional(object({
          action = string
        }), null)
        label_name_condition = optional(object({
          label_name = string
        }), null)
      }))
    }))
  })
  default = null
}
