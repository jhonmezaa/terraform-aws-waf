variable "region" {
  description = "AWS region to deploy resources."
  type        = string
  default     = "us-east-1"
}

variable "account_name" {
  description = "Account name for resource naming."
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name for resource naming."
  type        = string
  default     = "myapp"
}
