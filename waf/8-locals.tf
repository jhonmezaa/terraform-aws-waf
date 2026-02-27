locals {
  # =============================================================================
  # Region Prefix Mapping
  # =============================================================================

  region_prefix_map = {
    # US Regions
    "us-east-1" = "ause1"
    "us-east-2" = "ause2"
    "us-west-1" = "ausw1"
    "us-west-2" = "ausw2"
    # EU Regions
    "eu-west-1"    = "euwe1"
    "eu-west-2"    = "euwe2"
    "eu-west-3"    = "euwe3"
    "eu-central-1" = "euce1"
    "eu-central-2" = "euce2"
    "eu-north-1"   = "euno1"
    "eu-south-1"   = "euso1"
    "eu-south-2"   = "euso2"
    # AP Regions
    "ap-southeast-1" = "apse1"
    "ap-southeast-2" = "apse2"
    "ap-southeast-3" = "apse3"
    "ap-southeast-4" = "apse4"
    "ap-northeast-1" = "apne1"
    "ap-northeast-2" = "apne2"
    "ap-northeast-3" = "apne3"
    "ap-south-1"     = "apso1"
    "ap-south-2"     = "apso2"
    "ap-east-1"      = "apea1"
    # SA Regions
    "sa-east-1" = "saea1"
    # CA Regions
    "ca-central-1" = "cace1"
    "ca-west-1"    = "cawe1"
    # ME Regions
    "me-south-1"   = "meso1"
    "me-central-1" = "mece1"
    # AF Regions
    "af-south-1" = "afso1"
    # IL Regions
    "il-central-1" = "ilce1"
  }

  region_prefix = var.region_prefix != null ? var.region_prefix : lookup(
    local.region_prefix_map,
    data.aws_region.current.id,
    data.aws_region.current.id
  )

  # Name prefix: includes region prefix with trailing dash, or empty string
  name_prefix = var.use_region_prefix ? "${local.region_prefix}-" : ""

  # =============================================================================
  # Resource Naming
  # =============================================================================

  waf_name   = "${local.name_prefix}waf-${var.account_name}-${var.project_name}"
  ipset_name = "${local.name_prefix}waf-ipset-${var.account_name}-${var.project_name}"
  regex_name = "${local.name_prefix}waf-regex-${var.account_name}-${var.project_name}"

  # =============================================================================
  # Common Tags
  # =============================================================================

  common_tags = merge(
    {
      Name      = local.waf_name
      ManagedBy = "Terraform"
    },
    var.tags
  )

  # =============================================================================
  # Rule Processing
  # =============================================================================

  byte_match_statement_rules = var.create && var.byte_match_statement_rules != null ? {
    for rule in var.byte_match_statement_rules :
    rule.name => rule
  } : {}

  geo_allowlist_statement_rules = var.create && var.geo_allowlist_statement_rules != null ? {
    for rule in var.geo_allowlist_statement_rules :
    rule.name => rule
  } : {}

  geo_match_statement_rules = var.create && var.geo_match_statement_rules != null ? {
    for rule in var.geo_match_statement_rules :
    rule.name => rule
  } : {}

  ip_set_reference_statement_rules = var.create && var.ip_set_reference_statement_rules != null ? {
    for rule in var.ip_set_reference_statement_rules :
    rule.name => rule
  } : {}

  managed_rule_group_statement_rules = var.create && var.managed_rule_group_statement_rules != null ? {
    for rule in var.managed_rule_group_statement_rules :
    rule.name => rule
  } : {}

  rate_based_statement_rules = var.create && var.rate_based_statement_rules != null ? {
    for rule in var.rate_based_statement_rules :
    rule.name => rule
  } : {}

  rule_group_reference_statement_rules = var.create && var.rule_group_reference_statement_rules != null ? {
    for rule in var.rule_group_reference_statement_rules :
    rule.name => rule
  } : {}

  regex_pattern_set_reference_statement_rules = var.create && var.regex_pattern_set_reference_statement_rules != null ? {
    for rule in var.regex_pattern_set_reference_statement_rules :
    rule.name => rule
  } : {}

  regex_match_statement_rules = var.create && var.regex_match_statement_rules != null ? {
    for rule in var.regex_match_statement_rules :
    rule.name => rule
  } : {}

  size_constraint_statement_rules = var.create && var.size_constraint_statement_rules != null ? {
    for rule in var.size_constraint_statement_rules :
    rule.name => rule
  } : {}

  sqli_match_statement_rules = var.create && var.sqli_match_statement_rules != null ? {
    for rule in var.sqli_match_statement_rules :
    rule.name => rule
  } : {}

  xss_match_statement_rules = var.create && var.xss_match_statement_rules != null ? {
    for rule in var.xss_match_statement_rules :
    rule.name => rule
  } : {}

  # =============================================================================
  # IP Set Processing (inline IP sets from rules)
  # =============================================================================

  inline_ip_sets = var.create && var.ip_set_reference_statement_rules != null ? {
    for rule in var.ip_set_reference_statement_rules :
    rule.name => rule.statement.ip_set
    if try(rule.statement.ip_set, null) != null && try(rule.statement.arn, null) == null
  } : {}

  ip_rule_to_ip_set = var.create && var.ip_set_reference_statement_rules != null ? {
    for rule in var.ip_set_reference_statement_rules :
    rule.name => rule.name
  } : {}

  # =============================================================================
  # Default Block Custom Response
  # =============================================================================

  default_custom_response_body_key = var.default_block_custom_response_body_key != null ? (
    contains(keys(var.custom_response_body), var.default_block_custom_response_body_key) ? var.default_block_custom_response_body_key : null
  ) : null
}
