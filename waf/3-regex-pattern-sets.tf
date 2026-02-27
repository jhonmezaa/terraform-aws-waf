# =============================================================================
# WAFv2 Regex Pattern Sets
# =============================================================================

resource "aws_wafv2_regex_pattern_set" "this" {
  for_each = local.regex_pattern_sets

  name        = "${local.resource_name}-regex-${each.key}"
  description = each.value.description
  scope       = each.value.scope

  dynamic "regular_expression" {
    for_each = each.value.regular_expression

    content {
      regex_string = regular_expression.value
    }
  }

  tags = merge(
    local.default_tags,
    {
      "Name" = "${local.resource_name}-regex-${each.key}"
    }
  )
}
