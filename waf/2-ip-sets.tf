# =============================================================================
# WAFv2 IP Sets
# =============================================================================

resource "aws_wafv2_ip_set" "this" {
  for_each = local.ip_sets

  name               = "${local.resource_name}-ipset-${each.key}"
  description        = each.value.description
  scope              = each.value.scope
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses

  tags = merge(
    local.default_tags,
    {
      "Name" = "${local.resource_name}-ipset-${each.key}"
    }
  )
}
