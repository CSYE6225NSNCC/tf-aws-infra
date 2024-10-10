variable "aws_region" {
  description = "The AWS region to deploy the resources"

}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
}

variable "availability_zones" {
  description = "Availability zones for the subnets"
  type        = list(string)
}

variable "aws_profile" {
  description = "AWS profile to use"
}