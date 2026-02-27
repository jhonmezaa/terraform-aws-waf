# =============================================================================
# WAF IP Sets
# =============================================================================
# IP Sets are created automatically when ip_set_reference_statement_rules
# include an inline ip_set definition (instead of an ARN).
# =============================================================================

resource "aws_wafv2_ip_set" "this" {
  for_each = local.inline_ip_sets

  name               = "${local.ipset_name}-${each.key}"
  description        = lookup(each.value, "description", "Managed by Terraform")
  scope              = var.scope
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses

  tags = merge(
    local.common_tags,
    {
      Name = "${local.ipset_name}-${each.key}"
    }
  )
}

# =============================================================================
# Standalone IP Sets
# =============================================================================
# Additional IP sets that can be created independently and referenced by ARN.
# =============================================================================

resource "aws_wafv2_ip_set" "standalone" {
  for_each = var.create ? var.ip_sets : {}

  name               = "${local.ipset_name}-${each.key}"
  description        = lookup(each.value, "description", "Managed by Terraform")
  scope              = var.scope
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses

  tags = merge(
    local.common_tags,
    {
      Name = "${local.ipset_name}-${each.key}"
    }
  )
}
