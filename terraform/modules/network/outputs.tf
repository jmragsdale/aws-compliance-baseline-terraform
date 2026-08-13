output "vpc_id" {
  description = "ID of the baseline VPC."
  value       = aws_vpc.baseline.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets."
  value       = [for s in aws_subnet.private : s.id]
}

output "default_security_group_id" {
  description = "ID of the emptied default security group."
  value       = aws_default_security_group.baseline.id
}

output "flow_log_id" {
  description = "ID of the VPC flow log delivering to the archive."
  value       = aws_flow_log.vpc.id
}

output "interface_endpoint_ids" {
  description = "Map of service short name to interface endpoint id."
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
}

output "gateway_endpoint_ids" {
  description = "Map of service short name to gateway endpoint id."
  value       = { for k, v in aws_vpc_endpoint.gateway : k => v.id }
}
