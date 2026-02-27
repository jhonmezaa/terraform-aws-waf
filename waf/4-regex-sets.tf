# =============================================================================
# WAF Regex Pattern Sets
# =============================================================================

resource "aws_wafv2_regex_pattern_set" "this" {
  for_each = var.create ? var.regex_pattern_sets : {}

  name        = "${local.regex_name}-${each.key}"
  description = lookup(each.value, "description", "Managed by Terraform")
  scope       = var.scope

  dynamic "regular_expression" {
    for_each = each.value.regular_expressions

    content {
      regex_string = regular_expression.value
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.regex_name}-${each.key}"
    }
  )
}
