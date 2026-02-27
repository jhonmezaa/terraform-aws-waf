locals {
  # =============================================================================
  # Region Prefix Mapping (29 regions)
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
  # Resource Name Generation
  # =============================================================================

  # Base name pattern: {prefix}waf-{account}-{project}
  resource_name = "${local.name_prefix}waf-${var.account_name}-${var.project_name}"

  # =============================================================================
  # Web ACL Processing
  # =============================================================================

  web_acls = var.create ? var.web_acls : {}

  # =============================================================================
  # IP Set Processing
  # =============================================================================

  ip_sets = var.create ? var.ip_sets : {}

  # =============================================================================
  # Regex Pattern Set Processing
  # =============================================================================

  regex_pattern_sets = var.create ? var.regex_pattern_sets : {}

  # =============================================================================
  # Rule Group Processing
  # =============================================================================

  rule_groups = var.create ? var.rule_groups : {}

  # =============================================================================
  # Logging Configuration Processing
  # =============================================================================

  logging_configurations = var.create ? var.logging_configurations : {}

  # =============================================================================
  # Association Processing
  # =============================================================================

  associations = var.create ? var.associations : {}

  # =============================================================================
  # Default Tags
  # =============================================================================

  default_tags = merge(
    {
      "ManagedBy" = "Terraform"
      "Module"    = "terraform-aws-waf"
    },
    var.tags
  )
}
