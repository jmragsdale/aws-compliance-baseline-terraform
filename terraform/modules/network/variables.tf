variable "name_prefix" {
  description = "Prefix for VPC, subnet, endpoint and flow log names."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource in this module."
  type        = map(string)
}

variable "vpc_cidr" {
  description = "CIDR block for the baseline VPC."
  type        = string
}

variable "availability_zone_count" {
  description = "Number of AZs to place private subnets in. The FedRAMP baseline sets the floor (CP-10)."
  type        = number

  validation {
    condition     = var.availability_zone_count >= 2 && var.availability_zone_count <= 4
    error_message = "availability_zone_count must be between 2 and 4."
  }
}

variable "log_archive_bucket_arn" {
  description = "ARN of the central log archive that flow logs are delivered to."
  type        = string
}

variable "flow_log_aggregation_seconds" {
  description = "Flow log aggregation interval. 60s at High, 600s at Moderate."
  type        = number

  validation {
    condition     = contains([60, 600], var.flow_log_aggregation_seconds)
    error_message = "flow_log_aggregation_seconds must be 60 or 600 (the only intervals VPC flow logs accept)."
  }
}

variable "enable_vpc_endpoints" {
  description = "Create the gateway and interface endpoints. Interface endpoints are metered per hour per AZ."
  type        = bool
  default     = false
}

variable "organization_id" {
  description = "Organization ID used in the endpoint policy perimeter condition."
  type        = string
}
