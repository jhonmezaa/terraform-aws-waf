# =============================================================================
# WAF Web ACL
# =============================================================================

resource "aws_wafv2_web_acl" "this" {
  count = var.create ? 1 : 0

  name          = local.waf_name
  description   = var.description
  scope         = var.scope
  token_domains = var.token_domains

  tags = local.common_tags

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [true] : []
      content {}
    }

    dynamic "block" {
      for_each = var.default_action == "block" ? [true] : []
      content {
        dynamic "custom_response" {
          for_each = var.default_block_response != null ? [true] : []
          content {
            response_code            = var.default_block_response
            custom_response_body_key = local.default_custom_response_body_key
          }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.visibility_config.cloudwatch_metrics_enabled
    metric_name                = var.visibility_config.metric_name
    sampled_requests_enabled   = var.visibility_config.sampled_requests_enabled
  }

  dynamic "custom_response_body" {
    for_each = var.custom_response_body
    content {
      key          = custom_response_body.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
    }
  }

  # ===========================================================================
  # Byte Match Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.byte_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
        dynamic "challenge" {
          for_each = rule.value.action == "challenge" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "byte_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            positional_constraint = byte_match_statement.value.positional_constraint
            search_string         = byte_match_statement.value.search_string

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? rule.value.statement.text_transformation : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Geo Allowlist Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.geo_allowlist_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "challenge" {
          for_each = rule.value.action == "challenge" ? [1] : []
          content {}
        }
      }

      statement {
        not_statement {
          statement {
            dynamic "geo_match_statement" {
              for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

              content {
                country_codes = geo_match_statement.value.country_codes

                dynamic "forwarded_ip_config" {
                  for_each = lookup(geo_match_statement.value, "forwarded_ip_config", null) != null ? [geo_match_statement.value.forwarded_ip_config] : []

                  content {
                    fallback_behavior = forwarded_ip_config.value.fallback_behavior
                    header_name       = forwarded_ip_config.value.header_name
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }
    }
  }

  # ===========================================================================
  # Geo Match Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.geo_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "geo_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            country_codes = geo_match_statement.value.country_codes

            dynamic "forwarded_ip_config" {
              for_each = lookup(geo_match_statement.value, "forwarded_ip_config", null) != null ? [geo_match_statement.value.forwarded_ip_config] : []

              content {
                fallback_behavior = forwarded_ip_config.value.fallback_behavior
                header_name       = forwarded_ip_config.value.header_name
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # IP Set Reference Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.ip_set_reference_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "ip_set_reference_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            arn = try(aws_wafv2_ip_set.this[local.ip_rule_to_ip_set[rule.key]], null) != null ? aws_wafv2_ip_set.this[local.ip_rule_to_ip_set[rule.key]].arn : ip_set_reference_statement.value.arn

            dynamic "ip_set_forwarded_ip_config" {
              for_each = lookup(ip_set_reference_statement.value, "ip_set_forwarded_ip_config", null) != null ? [ip_set_reference_statement.value.ip_set_forwarded_ip_config] : []

              content {
                fallback_behavior = ip_set_forwarded_ip_config.value.fallback_behavior
                header_name       = ip_set_forwarded_ip_config.value.header_name
                position          = ip_set_forwarded_ip_config.value.position
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Managed Rule Group Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.managed_rule_group_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = lookup(rule.value, "override_action", null) == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = lookup(rule.value, "override_action", null) != "count" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "managed_rule_group_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            name        = managed_rule_group_statement.value.name
            vendor_name = managed_rule_group_statement.value.vendor_name
            version     = lookup(managed_rule_group_statement.value, "version", null)

            dynamic "rule_action_override" {
              for_each = lookup(managed_rule_group_statement.value, "rule_action_override", null) != null ? managed_rule_group_statement.value.rule_action_override : {}

              content {
                name = rule_action_override.key

                action_to_use {
                  dynamic "allow" {
                    for_each = rule_action_override.value.action == "allow" ? [1] : []
                    content {
                      dynamic "custom_request_handling" {
                        for_each = lookup(rule_action_override.value, "custom_request_handling", null) != null ? [1] : []
                        content {
                          insert_header {
                            name  = rule_action_override.value.custom_request_handling.insert_header.name
                            value = rule_action_override.value.custom_request_handling.insert_header.value
                          }
                        }
                      }
                    }
                  }
                  dynamic "block" {
                    for_each = rule_action_override.value.action == "block" ? [1] : []
                    content {
                      dynamic "custom_response" {
                        for_each = lookup(rule_action_override.value, "custom_response", null) != null ? [1] : []
                        content {
                          response_code            = rule_action_override.value.custom_response.response_code
                          custom_response_body_key = lookup(rule_action_override.value.custom_response, "custom_response_body_key", null)
                          dynamic "response_header" {
                            for_each = lookup(rule_action_override.value.custom_response, "response_header", null) != null ? [1] : []
                            content {
                              name  = rule_action_override.value.custom_response.response_header.name
                              value = rule_action_override.value.custom_response.response_header.value
                            }
                          }
                        }
                      }
                    }
                  }
                  dynamic "count" {
                    for_each = rule_action_override.value.action == "count" ? [1] : []
                    content {
                      dynamic "custom_request_handling" {
                        for_each = lookup(rule_action_override.value, "custom_request_handling", null) != null ? [1] : []
                        content {
                          insert_header {
                            name  = rule_action_override.value.custom_request_handling.insert_header.name
                            value = rule_action_override.value.custom_request_handling.insert_header.value
                          }
                        }
                      }
                    }
                  }
                  dynamic "captcha" {
                    for_each = rule_action_override.value.action == "captcha" ? [1] : []
                    content {}
                  }
                  dynamic "challenge" {
                    for_each = rule_action_override.value.action == "challenge" ? [1] : []
                    content {}
                  }
                }
              }
            }

            # Managed rule group configs (Bot Control, ATP, ACFP, Anti-DDoS)
            dynamic "managed_rule_group_configs" {
              for_each = lookup(managed_rule_group_statement.value, "managed_rule_group_configs", null) != null ? managed_rule_group_statement.value.managed_rule_group_configs : []
              content {
                # Anti-DDoS rule set
                dynamic "aws_managed_rules_anti_ddos_rule_set" {
                  for_each = lookup(managed_rule_group_configs.value, "aws_managed_rules_anti_ddos_rule_set", null) != null ? [1] : []
                  content {
                    sensitivity_to_block = managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set.sensitivity_to_block
                    dynamic "client_side_action_config" {
                      for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set, "client_side_action_config", null) != null ? [managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set.client_side_action_config] : []
                      content {
                        challenge {
                          usage_of_action = managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set.client_side_action_config.challenge.usage_of_action
                          sensitivity     = lookup(managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set.client_side_action_config.challenge, "sensitivity", null)
                          dynamic "exempt_uri_regular_expression" {
                            for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set.client_side_action_config.challenge, "exempt_uri_regular_expression", null) != null ? managed_rule_group_configs.value.aws_managed_rules_anti_ddos_rule_set.client_side_action_config.challenge.exempt_uri_regular_expression : []
                            content {
                              regex_string = exempt_uri_regular_expression.value.regex_string
                            }
                          }
                        }
                      }
                    }
                  }
                }

                # Bot Control rule set
                dynamic "aws_managed_rules_bot_control_rule_set" {
                  for_each = lookup(managed_rule_group_configs.value, "aws_managed_rules_bot_control_rule_set", null) != null ? [1] : []
                  content {
                    inspection_level        = managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set.inspection_level
                    enable_machine_learning = lookup(managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set, "enable_machine_learning", true)
                  }
                }

                # ATP rule set
                dynamic "aws_managed_rules_atp_rule_set" {
                  for_each = lookup(managed_rule_group_configs.value, "aws_managed_rules_atp_rule_set", null) != null ? [1] : []
                  content {
                    enable_regex_in_path = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set, "enable_regex_in_path", null)
                    login_path           = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.login_path

                    dynamic "request_inspection" {
                      for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set, "request_inspection", null) != null ? [1] : []
                      content {
                        payload_type = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.request_inspection.payload_type
                        username_field {
                          identifier = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.request_inspection.username_field.identifier
                        }
                        password_field {
                          identifier = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.request_inspection.password_field.identifier
                        }
                      }
                    }

                    dynamic "response_inspection" {
                      for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set, "response_inspection", null) != null ? [1] : []
                      content {
                        dynamic "body_contains" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection, "body_contains", null) != null ? [1] : []
                          content {
                            failure_strings = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.body_contains.failure_strings
                            success_strings = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.body_contains.success_strings
                          }
                        }
                        dynamic "header" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection, "header", null) != null ? [1] : []
                          content {
                            failure_values = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.header.failure_values
                            name           = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.header.name
                            success_values = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.header.success_values
                          }
                        }
                        dynamic "json" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection, "json", null) != null ? [1] : []
                          content {
                            failure_values = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.json.failure_values
                            identifier     = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.json.identifier
                            success_values = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.json.success_values
                          }
                        }
                        dynamic "status_code" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection, "status_code", null) != null ? [1] : []
                          content {
                            failure_codes = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.status_code.failure_codes
                            success_codes = managed_rule_group_configs.value.aws_managed_rules_atp_rule_set.response_inspection.status_code.success_codes
                          }
                        }
                      }
                    }
                  }
                }

                # ACFP rule set
                dynamic "aws_managed_rules_acfp_rule_set" {
                  for_each = lookup(managed_rule_group_configs.value, "aws_managed_rules_acfp_rule_set", null) != null ? [1] : []
                  content {
                    creation_path          = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.creation_path
                    enable_regex_in_path   = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set, "enable_regex_in_path", true)
                    registration_page_path = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.registration_page_path

                    dynamic "request_inspection" {
                      for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set, "request_inspection", null) != null ? [1] : []
                      content {
                        payload_type = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection.payload_type
                        dynamic "username_field" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection, "username_field", null) != null ? [1] : []
                          content {
                            identifier = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection.username_field.identifier
                          }
                        }
                        dynamic "password_field" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection, "password_field", null) != null ? [1] : []
                          content {
                            identifier = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection.password_field.identifier
                          }
                        }
                        dynamic "email_field" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection, "email_field", null) != null ? [1] : []
                          content {
                            identifier = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection.email_field.identifier
                          }
                        }
                        dynamic "address_fields" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection, "address_fields", null) != null ? [1] : []
                          content {
                            identifiers = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection.address_fields.identifiers
                          }
                        }
                        dynamic "phone_number_fields" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection, "phone_number_fields", null) != null ? [1] : []
                          content {
                            identifiers = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.request_inspection.phone_number_fields.identifiers
                          }
                        }
                      }
                    }

                    dynamic "response_inspection" {
                      for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set, "response_inspection", null) != null ? [1] : []
                      content {
                        dynamic "body_contains" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection, "body_contains", null) != null ? [1] : []
                          content {
                            failure_strings = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.body_contains.failure_strings
                            success_strings = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.body_contains.success_strings
                          }
                        }
                        dynamic "header" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection, "header", null) != null ? [1] : []
                          content {
                            failure_values = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.header.failure_values
                            name           = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.header.name
                            success_values = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.header.success_values
                          }
                        }
                        dynamic "json" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection, "json", null) != null ? [1] : []
                          content {
                            failure_values = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.json.failure_values
                            identifier     = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.json.identifier
                            success_values = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.json.success_values
                          }
                        }
                        dynamic "status_code" {
                          for_each = lookup(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection, "status_code", null) != null ? [1] : []
                          content {
                            failure_codes = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.status_code.failure_codes
                            success_codes = managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set.response_inspection.status_code.success_codes
                          }
                        }
                      }
                    }
                  }
                }
              }
            }

            # Scope down statement (direct)
            dynamic "scope_down_statement" {
              for_each = lookup(managed_rule_group_statement.value, "scope_down_statement", null) != null && !lookup(managed_rule_group_statement.value, "scope_down_not_statement_enabled", false) ? [managed_rule_group_statement.value.scope_down_statement] : []

              content {
                dynamic "byte_match_statement" {
                  for_each = lookup(scope_down_statement.value, "byte_match_statement", null) != null ? [scope_down_statement.value.byte_match_statement] : []

                  content {
                    positional_constraint = byte_match_statement.value.positional_constraint
                    search_string         = byte_match_statement.value.search_string

                    dynamic "field_to_match" {
                      for_each = lookup(byte_match_statement.value, "field_to_match", null) != null ? [byte_match_statement.value.field_to_match] : []

                      content {
                        dynamic "all_query_arguments" {
                          for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "method" {
                          for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "query_string" {
                          for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "single_header" {
                          for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                          content {
                            name = single_header.value.name
                          }
                        }
                        dynamic "single_query_argument" {
                          for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                          content {
                            name = single_query_argument.value.name
                          }
                        }
                        dynamic "uri_path" {
                          for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                          content {}
                        }
                      }
                    }

                    dynamic "text_transformation" {
                      for_each = lookup(byte_match_statement.value, "text_transformation", null) != null ? byte_match_statement.value.text_transformation : []

                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
              }
            }

            # Scope down statement (with NOT)
            dynamic "scope_down_statement" {
              for_each = lookup(managed_rule_group_statement.value, "scope_down_statement", null) != null && lookup(managed_rule_group_statement.value, "scope_down_not_statement_enabled", false) ? [managed_rule_group_statement.value.scope_down_statement] : []

              content {
                not_statement {
                  statement {
                    dynamic "byte_match_statement" {
                      for_each = lookup(scope_down_statement.value, "byte_match_statement", null) != null ? [scope_down_statement.value.byte_match_statement] : []

                      content {
                        positional_constraint = byte_match_statement.value.positional_constraint
                        search_string         = byte_match_statement.value.search_string

                        dynamic "field_to_match" {
                          for_each = lookup(byte_match_statement.value, "field_to_match", null) != null ? [byte_match_statement.value.field_to_match] : []

                          content {
                            dynamic "all_query_arguments" {
                              for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                              content {}
                            }
                            dynamic "body" {
                              for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                              content {}
                            }
                            dynamic "method" {
                              for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                              content {}
                            }
                            dynamic "query_string" {
                              for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                              content {}
                            }
                            dynamic "single_header" {
                              for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                              content {
                                name = single_header.value.name
                              }
                            }
                            dynamic "single_query_argument" {
                              for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                              content {
                                name = single_query_argument.value.name
                              }
                            }
                            dynamic "uri_path" {
                              for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                              content {}
                            }
                          }
                        }

                        dynamic "text_transformation" {
                          for_each = lookup(byte_match_statement.value, "text_transformation", null) != null ? byte_match_statement.value.text_transformation : []

                          content {
                            priority = text_transformation.value.priority
                            type     = text_transformation.value.type
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Rule Group Reference Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.rule_group_reference_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = lookup(rule.value, "override_action", null) == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = lookup(rule.value, "override_action", null) != "count" ? [1] : []
          content {}
        }
      }

      statement {
        rule_group_reference_statement {
          arn = rule.value.statement.arn

          dynamic "rule_action_override" {
            for_each = lookup(rule.value.statement, "rule_action_override", null) != null ? rule.value.statement.rule_action_override : {}

            content {
              name = rule_action_override.key

              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Rate Based Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.rate_based_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "rate_based_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            aggregate_key_type    = lookup(rate_based_statement.value, "aggregate_key_type", "IP")
            limit                 = rate_based_statement.value.limit
            evaluation_window_sec = lookup(rate_based_statement.value, "evaluation_window_sec", 300)

            dynamic "forwarded_ip_config" {
              for_each = lookup(rate_based_statement.value, "forwarded_ip_config", null) != null ? [rate_based_statement.value.forwarded_ip_config] : []

              content {
                fallback_behavior = forwarded_ip_config.value.fallback_behavior
                header_name       = forwarded_ip_config.value.header_name
              }
            }

            dynamic "custom_key" {
              for_each = lookup(rate_based_statement.value, "custom_key", null) != null ? rate_based_statement.value.custom_key : []

              content {
                dynamic "ip" {
                  for_each = lookup(custom_key.value, "ip", null) != null ? [1] : []
                  content {}
                }

                dynamic "header" {
                  for_each = lookup(custom_key.value, "header", null) != null ? [custom_key.value.header] : []

                  content {
                    name = header.value.name

                    dynamic "text_transformation" {
                      for_each = lookup(header.value, "text_transformation", null) != null ? header.value.text_transformation : []

                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
              }
            }

            dynamic "scope_down_statement" {
              for_each = lookup(rate_based_statement.value, "scope_down_statement", null) != null ? [rate_based_statement.value.scope_down_statement] : []

              content {
                dynamic "byte_match_statement" {
                  for_each = lookup(scope_down_statement.value, "byte_match_statement", null) != null ? [scope_down_statement.value.byte_match_statement] : []

                  content {
                    positional_constraint = byte_match_statement.value.positional_constraint
                    search_string         = byte_match_statement.value.search_string

                    dynamic "field_to_match" {
                      for_each = lookup(byte_match_statement.value, "field_to_match", null) != null ? [byte_match_statement.value.field_to_match] : []

                      content {
                        dynamic "all_query_arguments" {
                          for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "method" {
                          for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "query_string" {
                          for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                          content {}
                        }
                        dynamic "single_header" {
                          for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                          content {
                            name = single_header.value.name
                          }
                        }
                        dynamic "single_query_argument" {
                          for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                          content {
                            name = single_query_argument.value.name
                          }
                        }
                        dynamic "uri_path" {
                          for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                          content {}
                        }
                      }
                    }

                    dynamic "text_transformation" {
                      for_each = lookup(byte_match_statement.value, "text_transformation", null) != null ? byte_match_statement.value.text_transformation : []

                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Regex Pattern Set Reference Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.regex_pattern_set_reference_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "regex_pattern_set_reference_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            arn = regex_pattern_set_reference_statement.value.arn

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? rule.value.statement.text_transformation : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Regex Match Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.regex_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "regex_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            regex_string = regex_match_statement.value.regex_string

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? rule.value.statement.text_transformation : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # Size Constraint Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.size_constraint_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "size_constraint_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            comparison_operator = size_constraint_statement.value.comparison_operator
            size                = size_constraint_statement.value.size

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? rule.value.statement.text_transformation : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # SQLi Match Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.sqli_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "sqli_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? rule.value.statement.text_transformation : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # ===========================================================================
  # XSS Match Statement Rules
  # ===========================================================================

  dynamic "rule" {
    for_each = local.xss_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = lookup(rule.value, "custom_response", null) != null ? [rule.value.custom_response] : []
              content {
                response_code            = custom_response.value.response_code
                custom_response_body_key = lookup(custom_response.value, "custom_response_body_key", null)
                dynamic "response_header" {
                  for_each = lookup(custom_response.value, "response_header", null) != null ? [custom_response.value.response_header] : []
                  content {
                    name  = response_header.value.name
                    value = response_header.value.value
                  }
                }
              }
            }
          }
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "xss_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? rule.value.statement.text_transformation : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }

      dynamic "captcha_config" {
        for_each = lookup(rule.value, "captcha_config", null) != null ? [rule.value.captcha_config] : []

        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time_property.immunity_time
          }
        }
      }

      dynamic "rule_label" {
        for_each = lookup(rule.value, "rule_label", null) != null ? rule.value.rule_label : []
        content {
          name = rule_label.value
        }
      }
    }
  }
}
