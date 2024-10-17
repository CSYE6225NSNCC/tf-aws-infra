variable "aws_region" {
  description = "The AWS region to deploy the resources"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
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
  type        = string
}

##Variables for ec2 and security group

variable "custom_ami_id" {
  description = "The ID of the custom AMI to use."
  type        = string
}

variable "instance_type" {
  description = "The type of EC2 instance."
  default     = "t2.micro" // Adjust according to your needs
}

variable "application_port" {
  description = "The port on which the application runs."
  default     = 3000 // Replace with your application's port
}

variable "key_name" {
  default = "ubuntu"
}