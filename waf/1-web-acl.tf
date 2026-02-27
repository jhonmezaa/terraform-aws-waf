# =============================================================================
# WAFv2 Web ACL
# =============================================================================

resource "aws_wafv2_web_acl" "this" {
  for_each = local.web_acls

  name          = "${local.resource_name}-${each.key}"
  description   = each.value.description
  scope         = each.value.scope
  token_domains = each.value.token_domains

  # =========================================================================
  # Default Action
  # =========================================================================

  default_action {
    dynamic "allow" {
      for_each = each.value.default_action == "allow" ? [1] : []
      content {}
    }

    dynamic "block" {
      for_each = each.value.default_action == "block" ? [1] : []
      content {
        dynamic "custom_response" {
          for_each = each.value.default_block_response_code != null ? [1] : []
          content {
            response_code            = each.value.default_block_response_code
            custom_response_body_key = each.value.default_block_response_body_key
          }
        }
      }
    }
  }

  # =========================================================================
  # Custom Response Bodies
  # =========================================================================

  dynamic "custom_response_body" {
    for_each = each.value.custom_response_body

    content {
      key          = custom_response_body.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
    }
  }

  # =========================================================================
  # Captcha Config (ACL-level)
  # =========================================================================

  dynamic "captcha_config" {
    for_each = each.value.captcha_config != null ? [each.value.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time
      }
    }
  }

  # =========================================================================
  # Challenge Config (ACL-level)
  # =========================================================================

  dynamic "challenge_config" {
    for_each = each.value.challenge_config != null ? [each.value.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time
      }
    }
  }

  # =========================================================================
  # Association Config (request body inspection limits)
  # =========================================================================

  dynamic "association_config" {
    for_each = each.value.association_config != null ? [each.value.association_config] : []
    content {
      dynamic "request_body" {
        for_each = association_config.value.request_body != null ? association_config.value.request_body : {}
        content {
          dynamic "cloudfront" {
            for_each = request_body.key == "cloudfront" ? [request_body.value] : []
            content {
              default_size_inspection_limit = cloudfront.value.default_size_inspection_limit
            }
          }
          dynamic "api_gateway" {
            for_each = request_body.key == "api_gateway" ? [request_body.value] : []
            content {
              default_size_inspection_limit = api_gateway.value.default_size_inspection_limit
            }
          }
          dynamic "app_runner_service" {
            for_each = request_body.key == "app_runner_service" ? [request_body.value] : []
            content {
              default_size_inspection_limit = app_runner_service.value.default_size_inspection_limit
            }
          }
          dynamic "cognito_user_pool" {
            for_each = request_body.key == "cognito_user_pool" ? [request_body.value] : []
            content {
              default_size_inspection_limit = cognito_user_pool.value.default_size_inspection_limit
            }
          }
          dynamic "verified_access_instance" {
            for_each = request_body.key == "verified_access_instance" ? [request_body.value] : []
            content {
              default_size_inspection_limit = verified_access_instance.value.default_size_inspection_limit
            }
          }
        }
      }
    }
  }

  # =========================================================================
  # Rules
  # =========================================================================

  dynamic "rule" {
    for_each = each.value.rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      # --- Action (for non-group rules) ---
      dynamic "action" {
        for_each = rule.value.action != null ? [rule.value.action] : []
        content {
          dynamic "allow" {
            for_each = action.value == "allow" ? [1] : []
            content {}
          }
          dynamic "block" {
            for_each = action.value == "block" ? [1] : []
            content {
              dynamic "custom_response" {
                for_each = rule.value.custom_response != null ? [rule.value.custom_response] : []
                content {
                  response_code            = custom_response.value.response_code
                  custom_response_body_key = custom_response.value.custom_response_body_key
                  dynamic "response_header" {
                    for_each = custom_response.value.response_headers != null ? custom_response.value.response_headers : []
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
            for_each = action.value == "count" ? [1] : []
            content {}
          }
          dynamic "captcha" {
            for_each = action.value == "captcha" ? [1] : []
            content {}
          }
          dynamic "challenge" {
            for_each = action.value == "challenge" ? [1] : []
            content {}
          }
        }
      }

      # --- Override Action (for managed rule groups and rule group references) ---
      dynamic "override_action" {
        for_each = rule.value.override_action != null ? [rule.value.override_action] : []
        content {
          dynamic "count" {
            for_each = override_action.value == "count" ? [1] : []
            content {}
          }
          dynamic "none" {
            for_each = override_action.value == "none" ? [1] : []
            content {}
          }
        }
      }

      # --- Statement ---
      statement {

        # ===== Managed Rule Group Statement =====
        dynamic "managed_rule_group_statement" {
          for_each = rule.value.managed_rule_group_statement != null ? [rule.value.managed_rule_group_statement] : []
          content {
            name        = managed_rule_group_statement.value.name
            vendor_name = managed_rule_group_statement.value.vendor_name
            version     = managed_rule_group_statement.value.version

            dynamic "rule_action_override" {
              for_each = managed_rule_group_statement.value.rule_action_overrides != null ? {
                for override in managed_rule_group_statement.value.rule_action_overrides : override.name => override
              } : {}
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

            dynamic "managed_rule_group_configs" {
              for_each = managed_rule_group_statement.value.managed_rule_group_configs != null ? managed_rule_group_statement.value.managed_rule_group_configs : []
              content {
                dynamic "aws_managed_rules_bot_control_rule_set" {
                  for_each = try(managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_bot_control_rule_set] : []
                  content {
                    inspection_level        = aws_managed_rules_bot_control_rule_set.value.inspection_level
                    enable_machine_learning = try(aws_managed_rules_bot_control_rule_set.value.enable_machine_learning, true)
                  }
                }

                dynamic "aws_managed_rules_atp_rule_set" {
                  for_each = try(managed_rule_group_configs.value.aws_managed_rules_atp_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_atp_rule_set] : []
                  content {
                    enable_regex_in_path = try(aws_managed_rules_atp_rule_set.value.enable_regex_in_path, null)
                    login_path           = aws_managed_rules_atp_rule_set.value.login_path

                    dynamic "request_inspection" {
                      for_each = try(aws_managed_rules_atp_rule_set.value.request_inspection, null) != null ? [aws_managed_rules_atp_rule_set.value.request_inspection] : []
                      content {
                        payload_type = request_inspection.value.payload_type
                        username_field {
                          identifier = request_inspection.value.username_field.identifier
                        }
                        password_field {
                          identifier = request_inspection.value.password_field.identifier
                        }
                      }
                    }

                    dynamic "response_inspection" {
                      for_each = try(aws_managed_rules_atp_rule_set.value.response_inspection, null) != null ? [aws_managed_rules_atp_rule_set.value.response_inspection] : []
                      content {
                        dynamic "body_contains" {
                          for_each = try(response_inspection.value.body_contains, null) != null ? [response_inspection.value.body_contains] : []
                          content {
                            success_strings = body_contains.value.success_strings
                            failure_strings = body_contains.value.failure_strings
                          }
                        }
                        dynamic "header" {
                          for_each = try(response_inspection.value.header, null) != null ? [response_inspection.value.header] : []
                          content {
                            name           = header.value.name
                            success_values = header.value.success_values
                            failure_values = header.value.failure_values
                          }
                        }
                        dynamic "json" {
                          for_each = try(response_inspection.value.json, null) != null ? [response_inspection.value.json] : []
                          content {
                            identifier     = json.value.identifier
                            success_values = json.value.success_values
                            failure_values = json.value.failure_values
                          }
                        }
                        dynamic "status_code" {
                          for_each = try(response_inspection.value.status_code, null) != null ? [response_inspection.value.status_code] : []
                          content {
                            success_codes = status_code.value.success_codes
                            failure_codes = status_code.value.failure_codes
                          }
                        }
                      }
                    }
                  }
                }

                dynamic "aws_managed_rules_acfp_rule_set" {
                  for_each = try(managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set, null) != null ? [managed_rule_group_configs.value.aws_managed_rules_acfp_rule_set] : []
                  content {
                    creation_path          = aws_managed_rules_acfp_rule_set.value.creation_path
                    enable_regex_in_path   = try(aws_managed_rules_acfp_rule_set.value.enable_regex_in_path, null)
                    registration_page_path = aws_managed_rules_acfp_rule_set.value.registration_page_path

                    dynamic "request_inspection" {
                      for_each = try(aws_managed_rules_acfp_rule_set.value.request_inspection, null) != null ? [aws_managed_rules_acfp_rule_set.value.request_inspection] : []
                      content {
                        payload_type = request_inspection.value.payload_type
                        dynamic "username_field" {
                          for_each = try(request_inspection.value.username_field, null) != null ? [request_inspection.value.username_field] : []
                          content {
                            identifier = username_field.value.identifier
                          }
                        }
                        dynamic "password_field" {
                          for_each = try(request_inspection.value.password_field, null) != null ? [request_inspection.value.password_field] : []
                          content {
                            identifier = password_field.value.identifier
                          }
                        }
                        dynamic "email_field" {
                          for_each = try(request_inspection.value.email_field, null) != null ? [request_inspection.value.email_field] : []
                          content {
                            identifier = email_field.value.identifier
                          }
                        }
                      }
                    }
                  }
                }
              }
            }

            # Scope-down statement for managed rule groups (byte_match_statement level)
            dynamic "scope_down_statement" {
              for_each = managed_rule_group_statement.value.scope_down_statement != null ? [managed_rule_group_statement.value.scope_down_statement] : []
              content {
                dynamic "byte_match_statement" {
                  for_each = try(scope_down_statement.value.byte_match_statement, null) != null ? [scope_down_statement.value.byte_match_statement] : []
                  content {
                    positional_constraint = byte_match_statement.value.positional_constraint
                    search_string         = byte_match_statement.value.search_string

                    dynamic "field_to_match" {
                      for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                      content {
                        dynamic "all_query_arguments" {
                          for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = try(field_to_match.value.body, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "method" {
                          for_each = try(field_to_match.value.method, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "query_string" {
                          for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "single_header" {
                          for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                          content {
                            name = single_header.value.name
                          }
                        }
                        dynamic "single_query_argument" {
                          for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                          content {
                            name = single_query_argument.value.name
                          }
                        }
                        dynamic "uri_path" {
                          for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                          content {}
                        }
                      }
                    }

                    dynamic "text_transformation" {
                      for_each = try(byte_match_statement.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }

                dynamic "geo_match_statement" {
                  for_each = try(scope_down_statement.value.geo_match_statement, null) != null ? [scope_down_statement.value.geo_match_statement] : []
                  content {
                    country_codes = geo_match_statement.value.country_codes
                    dynamic "forwarded_ip_config" {
                      for_each = try(geo_match_statement.value.forwarded_ip_config, null) != null ? [geo_match_statement.value.forwarded_ip_config] : []
                      content {
                        fallback_behavior = forwarded_ip_config.value.fallback_behavior
                        header_name       = forwarded_ip_config.value.header_name
                      }
                    }
                  }
                }

                dynamic "ip_set_reference_statement" {
                  for_each = try(scope_down_statement.value.ip_set_reference_statement, null) != null ? [scope_down_statement.value.ip_set_reference_statement] : []
                  content {
                    arn = try(ip_set_reference_statement.value.ip_set_key, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn
                  }
                }

                dynamic "not_statement" {
                  for_each = try(scope_down_statement.value.not_statement, null) != null ? [scope_down_statement.value.not_statement] : []
                  content {
                    statement {
                      dynamic "byte_match_statement" {
                        for_each = try(not_statement.value.statement.byte_match_statement, null) != null ? [not_statement.value.statement.byte_match_statement] : []
                        content {
                          positional_constraint = byte_match_statement.value.positional_constraint
                          search_string         = byte_match_statement.value.search_string
                          dynamic "field_to_match" {
                            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                            content {
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content {
                                  name = single_header.value.name
                                }
                              }
                              dynamic "query_string" {
                                for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                                content {}
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = try(byte_match_statement.value.text_transformation, [])
                            content {
                              priority = text_transformation.value.priority
                              type     = text_transformation.value.type
                            }
                          }
                        }
                      }

                      dynamic "geo_match_statement" {
                        for_each = try(not_statement.value.statement.geo_match_statement, null) != null ? [not_statement.value.statement.geo_match_statement] : []
                        content {
                          country_codes = geo_match_statement.value.country_codes
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }

        # ===== IP Set Reference Statement =====
        dynamic "ip_set_reference_statement" {
          for_each = rule.value.ip_set_reference_statement != null ? [rule.value.ip_set_reference_statement] : []
          content {
            arn = ip_set_reference_statement.value.ip_set_key != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn

            dynamic "ip_set_forwarded_ip_config" {
              for_each = ip_set_reference_statement.value.ip_set_forwarded_ip_config != null ? [ip_set_reference_statement.value.ip_set_forwarded_ip_config] : []
              content {
                fallback_behavior = ip_set_forwarded_ip_config.value.fallback_behavior
                header_name       = ip_set_forwarded_ip_config.value.header_name
                position          = ip_set_forwarded_ip_config.value.position
              }
            }
          }
        }

        # ===== Rate Based Statement =====
        dynamic "rate_based_statement" {
          for_each = rule.value.rate_based_statement != null ? [rule.value.rate_based_statement] : []
          content {
            limit                 = rate_based_statement.value.limit
            aggregate_key_type    = rate_based_statement.value.aggregate_key_type
            evaluation_window_sec = rate_based_statement.value.evaluation_window_sec

            dynamic "forwarded_ip_config" {
              for_each = rate_based_statement.value.forwarded_ip_config != null ? [rate_based_statement.value.forwarded_ip_config] : []
              content {
                fallback_behavior = forwarded_ip_config.value.fallback_behavior
                header_name       = forwarded_ip_config.value.header_name
              }
            }

            dynamic "custom_key" {
              for_each = rate_based_statement.value.custom_keys != null ? rate_based_statement.value.custom_keys : []
              content {
                dynamic "ip" {
                  for_each = try(custom_key.value.ip, null) != null ? [1] : []
                  content {}
                }
                dynamic "header" {
                  for_each = try(custom_key.value.header, null) != null ? [custom_key.value.header] : []
                  content {
                    name = header.value.name
                    dynamic "text_transformation" {
                      for_each = try(header.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
                dynamic "query_string" {
                  for_each = try(custom_key.value.query_string, null) != null ? [custom_key.value.query_string] : []
                  content {
                    dynamic "text_transformation" {
                      for_each = try(query_string.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
                dynamic "uri_path" {
                  for_each = try(custom_key.value.uri_path, null) != null ? [custom_key.value.uri_path] : []
                  content {
                    dynamic "text_transformation" {
                      for_each = try(uri_path.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
                dynamic "cookie" {
                  for_each = try(custom_key.value.cookie, null) != null ? [custom_key.value.cookie] : []
                  content {
                    name = cookie.value.name
                    dynamic "text_transformation" {
                      for_each = try(cookie.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }
              }
            }

            # Scope-down statement for rate-based rules
            dynamic "scope_down_statement" {
              for_each = rate_based_statement.value.scope_down_statement != null ? [rate_based_statement.value.scope_down_statement] : []
              content {
                dynamic "byte_match_statement" {
                  for_each = try(scope_down_statement.value.byte_match_statement, null) != null ? [scope_down_statement.value.byte_match_statement] : []
                  content {
                    positional_constraint = byte_match_statement.value.positional_constraint
                    search_string         = byte_match_statement.value.search_string
                    dynamic "field_to_match" {
                      for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                      content {
                        dynamic "uri_path" {
                          for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "single_header" {
                          for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                          content {
                            name = single_header.value.name
                          }
                        }
                        dynamic "query_string" {
                          for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "all_query_arguments" {
                          for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = try(field_to_match.value.body, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "method" {
                          for_each = try(field_to_match.value.method, null) != null ? [1] : []
                          content {}
                        }
                      }
                    }
                    dynamic "text_transformation" {
                      for_each = try(byte_match_statement.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }

                dynamic "geo_match_statement" {
                  for_each = try(scope_down_statement.value.geo_match_statement, null) != null ? [scope_down_statement.value.geo_match_statement] : []
                  content {
                    country_codes = geo_match_statement.value.country_codes
                  }
                }

                dynamic "ip_set_reference_statement" {
                  for_each = try(scope_down_statement.value.ip_set_reference_statement, null) != null ? [scope_down_statement.value.ip_set_reference_statement] : []
                  content {
                    arn = try(ip_set_reference_statement.value.ip_set_key, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn
                  }
                }
              }
            }
          }
        }

        # ===== Byte Match Statement =====
        dynamic "byte_match_statement" {
          for_each = rule.value.byte_match_statement != null ? [rule.value.byte_match_statement] : []
          content {
            positional_constraint = byte_match_statement.value.positional_constraint
            search_string         = byte_match_statement.value.search_string

            dynamic "field_to_match" {
              for_each = byte_match_statement.value.field_to_match != null ? [byte_match_statement.value.field_to_match] : []
              content {
                dynamic "all_query_arguments" {
                  for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = try(field_to_match.value.body, null) != null ? [1] : []
                  content {
                    oversize_handling = try(field_to_match.value.body.oversize_handling, null)
                  }
                }
                dynamic "method" {
                  for_each = try(field_to_match.value.method, null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                  content {}
                }
                dynamic "headers" {
                  for_each = try(field_to_match.value.headers, null) != null ? [field_to_match.value.headers] : []
                  content {
                    match_scope       = headers.value.match_scope
                    oversize_handling = headers.value.oversize_handling
                    dynamic "match_pattern" {
                      for_each = [headers.value.match_pattern]
                      content {
                        dynamic "all" {
                          for_each = try(match_pattern.value.all, null) != null ? [1] : []
                          content {}
                        }
                        included_headers = try(match_pattern.value.included_headers, null)
                        excluded_headers = try(match_pattern.value.excluded_headers, null)
                      }
                    }
                  }
                }
                dynamic "json_body" {
                  for_each = try(field_to_match.value.json_body, null) != null ? [field_to_match.value.json_body] : []
                  content {
                    match_scope               = json_body.value.match_scope
                    invalid_fallback_behavior = try(json_body.value.invalid_fallback_behavior, null)
                    oversize_handling         = try(json_body.value.oversize_handling, null)
                    dynamic "match_pattern" {
                      for_each = [json_body.value.match_pattern]
                      content {
                        dynamic "all" {
                          for_each = try(match_pattern.value.all, null) != null ? [1] : []
                          content {}
                        }
                        included_paths = try(match_pattern.value.included_paths, null)
                      }
                    }
                  }
                }
                dynamic "cookies" {
                  for_each = try(field_to_match.value.cookies, null) != null ? [field_to_match.value.cookies] : []
                  content {
                    match_scope       = cookies.value.match_scope
                    oversize_handling = cookies.value.oversize_handling
                    dynamic "match_pattern" {
                      for_each = [cookies.value.match_pattern]
                      content {
                        dynamic "all" {
                          for_each = try(match_pattern.value.all, null) != null ? [1] : []
                          content {}
                        }
                        included_cookies = try(match_pattern.value.included_cookies, null)
                        excluded_cookies = try(match_pattern.value.excluded_cookies, null)
                      }
                    }
                  }
                }
              }
            }

            dynamic "text_transformation" {
              for_each = byte_match_statement.value.text_transformation
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }

        # ===== Size Constraint Statement =====
        dynamic "size_constraint_statement" {
          for_each = rule.value.size_constraint_statement != null ? [rule.value.size_constraint_statement] : []
          content {
            comparison_operator = size_constraint_statement.value.comparison_operator
            size                = size_constraint_statement.value.size

            dynamic "field_to_match" {
              for_each = size_constraint_statement.value.field_to_match != null ? [size_constraint_statement.value.field_to_match] : []
              content {
                dynamic "all_query_arguments" {
                  for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = try(field_to_match.value.body, null) != null ? [1] : []
                  content {
                    oversize_handling = try(field_to_match.value.body.oversize_handling, null)
                  }
                }
                dynamic "method" {
                  for_each = try(field_to_match.value.method, null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = size_constraint_statement.value.text_transformation
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }

        # ===== Geo Match Statement =====
        dynamic "geo_match_statement" {
          for_each = rule.value.geo_match_statement != null ? [rule.value.geo_match_statement] : []
          content {
            country_codes = geo_match_statement.value.country_codes

            dynamic "forwarded_ip_config" {
              for_each = geo_match_statement.value.forwarded_ip_config != null ? [geo_match_statement.value.forwarded_ip_config] : []
              content {
                fallback_behavior = forwarded_ip_config.value.fallback_behavior
                header_name       = forwarded_ip_config.value.header_name
              }
            }
          }
        }

        # ===== Regex Pattern Set Reference Statement =====
        dynamic "regex_pattern_set_reference_statement" {
          for_each = rule.value.regex_pattern_set_reference_statement != null ? [rule.value.regex_pattern_set_reference_statement] : []
          content {
            arn = regex_pattern_set_reference_statement.value.regex_set_key != null ? aws_wafv2_regex_pattern_set.this[regex_pattern_set_reference_statement.value.regex_set_key].arn : regex_pattern_set_reference_statement.value.arn

            dynamic "field_to_match" {
              for_each = regex_pattern_set_reference_statement.value.field_to_match != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []
              content {
                dynamic "all_query_arguments" {
                  for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = try(field_to_match.value.body, null) != null ? [1] : []
                  content {}
                }
                dynamic "method" {
                  for_each = try(field_to_match.value.method, null) != null ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                  content {}
                }
                dynamic "single_header" {
                  for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                  content {
                    name = single_header.value.name
                  }
                }
                dynamic "single_query_argument" {
                  for_each = try(field_to_match.value.single_query_argument, null) != null ? [field_to_match.value.single_query_argument] : []
                  content {
                    name = single_query_argument.value.name
                  }
                }
                dynamic "uri_path" {
                  for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = regex_pattern_set_reference_statement.value.text_transformation
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }

        # ===== Rule Group Reference Statement =====
        dynamic "rule_group_reference_statement" {
          for_each = rule.value.rule_group_reference_statement != null ? [rule.value.rule_group_reference_statement] : []
          content {
            arn = rule_group_reference_statement.value.rule_group_key != null ? aws_wafv2_rule_group.this[rule_group_reference_statement.value.rule_group_key].arn : rule_group_reference_statement.value.arn

            dynamic "rule_action_override" {
              for_each = rule_group_reference_statement.value.rule_action_overrides != null ? {
                for override in rule_group_reference_statement.value.rule_action_overrides : override.name => override
              } : {}
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

        # ===== Label Match Statement =====
        dynamic "label_match_statement" {
          for_each = rule.value.label_match_statement != null ? [rule.value.label_match_statement] : []
          content {
            scope = label_match_statement.value.scope
            key   = label_match_statement.value.key
          }
        }

        # ===== AND Statement (up to 2 levels deep) =====
        dynamic "and_statement" {
          for_each = rule.value.and_statement != null ? [rule.value.and_statement] : []
          content {
            dynamic "statement" {
              for_each = and_statement.value.statements
              content {
                dynamic "byte_match_statement" {
                  for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                  content {
                    positional_constraint = byte_match_statement.value.positional_constraint
                    search_string         = byte_match_statement.value.search_string
                    dynamic "field_to_match" {
                      for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                      content {
                        dynamic "uri_path" {
                          for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "single_header" {
                          for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                          content {
                            name = single_header.value.name
                          }
                        }
                        dynamic "query_string" {
                          for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = try(field_to_match.value.body, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "method" {
                          for_each = try(field_to_match.value.method, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "all_query_arguments" {
                          for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                          content {}
                        }
                      }
                    }
                    dynamic "text_transformation" {
                      for_each = try(byte_match_statement.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }

                dynamic "geo_match_statement" {
                  for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                  content {
                    country_codes = geo_match_statement.value.country_codes
                    dynamic "forwarded_ip_config" {
                      for_each = try(geo_match_statement.value.forwarded_ip_config, null) != null ? [geo_match_statement.value.forwarded_ip_config] : []
                      content {
                        fallback_behavior = forwarded_ip_config.value.fallback_behavior
                        header_name       = forwarded_ip_config.value.header_name
                      }
                    }
                  }
                }

                dynamic "ip_set_reference_statement" {
                  for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                  content {
                    arn = try(ip_set_reference_statement.value.ip_set_key, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn
                  }
                }

                dynamic "label_match_statement" {
                  for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                  content {
                    scope = label_match_statement.value.scope
                    key   = label_match_statement.value.key
                  }
                }

                dynamic "size_constraint_statement" {
                  for_each = try(statement.value.size_constraint_statement, null) != null ? [statement.value.size_constraint_statement] : []
                  content {
                    comparison_operator = size_constraint_statement.value.comparison_operator
                    size                = size_constraint_statement.value.size
                    dynamic "field_to_match" {
                      for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                      content {
                        dynamic "uri_path" {
                          for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = try(field_to_match.value.body, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "query_string" {
                          for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                          content {}
                        }
                      }
                    }
                    dynamic "text_transformation" {
                      for_each = try(size_constraint_statement.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }

                dynamic "not_statement" {
                  for_each = try(statement.value.not_statement, null) != null ? [statement.value.not_statement] : []
                  content {
                    statement {
                      dynamic "geo_match_statement" {
                        for_each = try(not_statement.value.statement.geo_match_statement, null) != null ? [not_statement.value.statement.geo_match_statement] : []
                        content {
                          country_codes = geo_match_statement.value.country_codes
                        }
                      }
                      dynamic "ip_set_reference_statement" {
                        for_each = try(not_statement.value.statement.ip_set_reference_statement, null) != null ? [not_statement.value.statement.ip_set_reference_statement] : []
                        content {
                          arn = try(ip_set_reference_statement.value.ip_set_key, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn
                        }
                      }
                      dynamic "byte_match_statement" {
                        for_each = try(not_statement.value.statement.byte_match_statement, null) != null ? [not_statement.value.statement.byte_match_statement] : []
                        content {
                          positional_constraint = byte_match_statement.value.positional_constraint
                          search_string         = byte_match_statement.value.search_string
                          dynamic "field_to_match" {
                            for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                            content {
                              dynamic "uri_path" {
                                for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                                content {}
                              }
                              dynamic "single_header" {
                                for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                                content {
                                  name = single_header.value.name
                                }
                              }
                            }
                          }
                          dynamic "text_transformation" {
                            for_each = try(byte_match_statement.value.text_transformation, [])
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

        # ===== OR Statement (up to 2 levels deep) =====
        dynamic "or_statement" {
          for_each = rule.value.or_statement != null ? [rule.value.or_statement] : []
          content {
            dynamic "statement" {
              for_each = or_statement.value.statements
              content {
                dynamic "byte_match_statement" {
                  for_each = try(statement.value.byte_match_statement, null) != null ? [statement.value.byte_match_statement] : []
                  content {
                    positional_constraint = byte_match_statement.value.positional_constraint
                    search_string         = byte_match_statement.value.search_string
                    dynamic "field_to_match" {
                      for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                      content {
                        dynamic "uri_path" {
                          for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "single_header" {
                          for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                          content {
                            name = single_header.value.name
                          }
                        }
                        dynamic "query_string" {
                          for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "body" {
                          for_each = try(field_to_match.value.body, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "method" {
                          for_each = try(field_to_match.value.method, null) != null ? [1] : []
                          content {}
                        }
                        dynamic "all_query_arguments" {
                          for_each = try(field_to_match.value.all_query_arguments, null) != null ? [1] : []
                          content {}
                        }
                      }
                    }
                    dynamic "text_transformation" {
                      for_each = try(byte_match_statement.value.text_transformation, [])
                      content {
                        priority = text_transformation.value.priority
                        type     = text_transformation.value.type
                      }
                    }
                  }
                }

                dynamic "geo_match_statement" {
                  for_each = try(statement.value.geo_match_statement, null) != null ? [statement.value.geo_match_statement] : []
                  content {
                    country_codes = geo_match_statement.value.country_codes
                  }
                }

                dynamic "ip_set_reference_statement" {
                  for_each = try(statement.value.ip_set_reference_statement, null) != null ? [statement.value.ip_set_reference_statement] : []
                  content {
                    arn = try(ip_set_reference_statement.value.ip_set_key, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn
                  }
                }

                dynamic "label_match_statement" {
                  for_each = try(statement.value.label_match_statement, null) != null ? [statement.value.label_match_statement] : []
                  content {
                    scope = label_match_statement.value.scope
                    key   = label_match_statement.value.key
                  }
                }
              }
            }
          }
        }

        # ===== NOT Statement =====
        dynamic "not_statement" {
          for_each = rule.value.not_statement != null ? [rule.value.not_statement] : []
          content {
            statement {
              dynamic "byte_match_statement" {
                for_each = try(not_statement.value.statement.byte_match_statement, null) != null ? [not_statement.value.statement.byte_match_statement] : []
                content {
                  positional_constraint = byte_match_statement.value.positional_constraint
                  search_string         = byte_match_statement.value.search_string
                  dynamic "field_to_match" {
                    for_each = try(byte_match_statement.value.field_to_match, null) != null ? [byte_match_statement.value.field_to_match] : []
                    content {
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "single_header" {
                        for_each = try(field_to_match.value.single_header, null) != null ? [field_to_match.value.single_header] : []
                        content {
                          name = single_header.value.name
                        }
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "method" {
                        for_each = try(field_to_match.value.method, null) != null ? [1] : []
                        content {}
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = try(byte_match_statement.value.text_transformation, [])
                    content {
                      priority = text_transformation.value.priority
                      type     = text_transformation.value.type
                    }
                  }
                }
              }

              dynamic "geo_match_statement" {
                for_each = try(not_statement.value.statement.geo_match_statement, null) != null ? [not_statement.value.statement.geo_match_statement] : []
                content {
                  country_codes = geo_match_statement.value.country_codes
                }
              }

              dynamic "ip_set_reference_statement" {
                for_each = try(not_statement.value.statement.ip_set_reference_statement, null) != null ? [not_statement.value.statement.ip_set_reference_statement] : []
                content {
                  arn = try(ip_set_reference_statement.value.ip_set_key, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ip_set_key].arn : ip_set_reference_statement.value.arn
                }
              }

              dynamic "label_match_statement" {
                for_each = try(not_statement.value.statement.label_match_statement, null) != null ? [not_statement.value.statement.label_match_statement] : []
                content {
                  scope = label_match_statement.value.scope
                  key   = label_match_statement.value.key
                }
              }

              dynamic "size_constraint_statement" {
                for_each = try(not_statement.value.statement.size_constraint_statement, null) != null ? [not_statement.value.statement.size_constraint_statement] : []
                content {
                  comparison_operator = size_constraint_statement.value.comparison_operator
                  size                = size_constraint_statement.value.size
                  dynamic "field_to_match" {
                    for_each = try(size_constraint_statement.value.field_to_match, null) != null ? [size_constraint_statement.value.field_to_match] : []
                    content {
                      dynamic "uri_path" {
                        for_each = try(field_to_match.value.uri_path, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "body" {
                        for_each = try(field_to_match.value.body, null) != null ? [1] : []
                        content {}
                      }
                      dynamic "query_string" {
                        for_each = try(field_to_match.value.query_string, null) != null ? [1] : []
                        content {}
                      }
                    }
                  }
                  dynamic "text_transformation" {
                    for_each = try(size_constraint_statement.value.text_transformation, [])
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

      # --- Visibility Config ---
      visibility_config {
        cloudwatch_metrics_enabled = rule.value.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.value.visibility_config.metric_name
        sampled_requests_enabled   = rule.value.visibility_config.sampled_requests_enabled
      }

      # --- Captcha Config ---
      dynamic "captcha_config" {
        for_each = rule.value.captcha_config != null ? [rule.value.captcha_config] : []
        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time
          }
        }
      }

      # --- Challenge Config ---
      dynamic "challenge_config" {
        for_each = rule.value.challenge_config != null ? [rule.value.challenge_config] : []
        content {
          immunity_time_property {
            immunity_time = challenge_config.value.immunity_time
          }
        }
      }

      # --- Rule Labels ---
      dynamic "rule_label" {
        for_each = rule.value.rule_labels != null ? rule.value.rule_labels : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  # =========================================================================
  # Visibility Config (ACL-level)
  # =========================================================================

  visibility_config {
    cloudwatch_metrics_enabled = each.value.visibility_config.cloudwatch_metrics_enabled
    metric_name                = each.value.visibility_config.metric_name
    sampled_requests_enabled   = each.value.visibility_config.sampled_requests_enabled
  }

  tags = merge(
    local.default_tags,
    {
      "Name" = "${local.resource_name}-${each.key}"
    }
  )
}
