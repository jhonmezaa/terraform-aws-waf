# =============================================================================
# WAFv2 Rule Groups
# =============================================================================

resource "aws_wafv2_rule_group" "this" {
  for_each = local.rule_groups

  name        = "${local.resource_name}-rg-${each.key}"
  description = each.value.description
  scope       = each.value.scope
  capacity    = each.value.capacity

  dynamic "custom_response_body" {
    for_each = each.value.custom_response_body

    content {
      key          = custom_response_body.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
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

      # --- Action ---
      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = try(rule.value.custom_response, null) != null ? [rule.value.custom_response] : []
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

      # --- Statement ---
      statement {
        # ===== Byte Match Statement =====
        dynamic "byte_match_statement" {
          for_each = try(rule.value.byte_match_statement, null) != null ? [rule.value.byte_match_statement] : []
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

        # ===== IP Set Reference Statement =====
        dynamic "ip_set_reference_statement" {
          for_each = try(rule.value.ip_set_reference_statement, null) != null ? [rule.value.ip_set_reference_statement] : []
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

        # ===== Geo Match Statement =====
        dynamic "geo_match_statement" {
          for_each = try(rule.value.geo_match_statement, null) != null ? [rule.value.geo_match_statement] : []
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

        # ===== Size Constraint Statement =====
        dynamic "size_constraint_statement" {
          for_each = try(rule.value.size_constraint_statement, null) != null ? [rule.value.size_constraint_statement] : []
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

        # ===== Regex Pattern Set Reference Statement =====
        dynamic "regex_pattern_set_reference_statement" {
          for_each = try(rule.value.regex_pattern_set_reference_statement, null) != null ? [rule.value.regex_pattern_set_reference_statement] : []
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

        # ===== Label Match Statement =====
        dynamic "label_match_statement" {
          for_each = try(rule.value.label_match_statement, null) != null ? [rule.value.label_match_statement] : []
          content {
            scope = label_match_statement.value.scope
            key   = label_match_statement.value.key
          }
        }

        # ===== SQLi Match Statement =====
        dynamic "sqli_match_statement" {
          for_each = try(rule.value.sqli_match_statement, null) != null ? [rule.value.sqli_match_statement] : []
          content {
            dynamic "field_to_match" {
              for_each = sqli_match_statement.value.field_to_match != null ? [sqli_match_statement.value.field_to_match] : []
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
              for_each = sqli_match_statement.value.text_transformation
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }

            sensitivity_level = try(sqli_match_statement.value.sensitivity_level, null)
          }
        }

        # ===== XSS Match Statement =====
        dynamic "xss_match_statement" {
          for_each = try(rule.value.xss_match_statement, null) != null ? [rule.value.xss_match_statement] : []
          content {
            dynamic "field_to_match" {
              for_each = xss_match_statement.value.field_to_match != null ? [xss_match_statement.value.field_to_match] : []
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
              for_each = xss_match_statement.value.text_transformation
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
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
        for_each = try(rule.value.captcha_config, null) != null ? [rule.value.captcha_config] : []
        content {
          immunity_time_property {
            immunity_time = captcha_config.value.immunity_time
          }
        }
      }

      # --- Rule Labels ---
      dynamic "rule_label" {
        for_each = try(rule.value.rule_labels, null) != null ? rule.value.rule_labels : []
        content {
          name = rule_label.value
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = each.value.visibility_config.cloudwatch_metrics_enabled
    metric_name                = each.value.visibility_config.metric_name
    sampled_requests_enabled   = each.value.visibility_config.sampled_requests_enabled
  }

  tags = merge(
    local.default_tags,
    {
      "Name" = "${local.resource_name}-rg-${each.key}"
    }
  )
}
