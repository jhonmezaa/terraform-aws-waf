# =============================================================================
# WAF Web ACL Association
# =============================================================================
# Associates the WAF Web ACL with AWS resources.
# Supported resources: ALB, API Gateway, AppSync, Cognito User Pool,
# App Runner, Verified Access Instance.
#
# NOTE: Do not use this for CloudFront distributions.
# For CloudFront, set the web_acl_id on the aws_cloudfront_distribution resource.
# =============================================================================

resource "aws_wafv2_web_acl_association" "this" {
  for_each = var.create && length(var.association_resource_arns) > 0 ? toset(var.association_resource_arns) : toset([])

  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}
