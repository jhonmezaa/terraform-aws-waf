# =============================================================================
# WAFv2 Web ACL Association
# =============================================================================
# Associates a Web ACL with an AWS resource.
#
# Supported resources:
# - Application Load Balancer (ALB)
# - Amazon API Gateway REST API
# - Amazon AppSync GraphQL API
# - Amazon Cognito User Pool
# - AWS App Runner Service
# - AWS Verified Access Instance
#
# NOTE: Do NOT use this for CloudFront distributions.
# For CloudFront, use the `web_acl_id` property on the `aws_cloudfront_distribution` resource.

resource "aws_wafv2_web_acl_association" "this" {
  for_each = local.associations

  web_acl_arn  = aws_wafv2_web_acl.this[each.value.web_acl_key].arn
  resource_arn = each.value.resource_arn
}
