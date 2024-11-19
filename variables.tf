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


# RDS instance configuration

variable "db_identifier" {
  description = "The RDS instance identifier"
  type        = string
}

variable "db_engine" {
  description = "The database engine to use"
  type        = string
}

variable "db_instance_class" {
  description = "The instance class for the database"
  type        = string
}

variable "allocated_storage" {
  description = "The allocated storage in gigabytes"
  type        = number
}

variable "db_name" {
  description = "The name of the database"
  type        = string
}

variable "db_username" {
  description = "The master username for the database"
  type        = string
}

variable "db_password" {
  description = "The master password for the database"
  type        = string
  sensitive   = true
}



variable "db_parameter_group_name" {
  description = "The name of the parameter group"
  type        = string
}

variable "db_max_connections" {
  description = "The maximum number of connections for the database"
  type        = number
}

variable "db_port" {
  description = "The port on which the application runs."
}

variable "root_volume_size" {
  description = "The size of the root EBS volume in gigabytes"
  type        = number
}

variable "root_volume_type" {
  description = "The type of EBS volume"
  type        = string
}

variable "zone_id" {
  description = "The zone_id for the application"
  type        = string
}

variable "domain_name" {
  description = "The main domain name (e.g., subdomain.your-domain-name.tld)"
  type        = string
}

variable "desired_capacity" {
  description = "The desired number of EC2 instances"
  type        = number
}

variable "max_size" {
  description = "The maximum number of EC2 instances"
  type        = number
}

variable "min_size" {
  description = "The minimum number of EC2 instances"
  type        = number
}

variable "health_check_grace_period" {
  description = "The time, in seconds, before an instance is considered unhealthy"
  type        = number
}

variable "period" {
  description = "The duration, in seconds, during which a healthcheck is performed"
  type        = number
}

variable "statistic" {
  description = "The statistic type for the alarm"
  type        = string
}

variable "scale_up_threshold" {
  description = "THe scale up threshold for the alarm"
  type        = number
}

variable "scale_down_threshold" {
  description = "The scale down threshold for the alarm"
  type        = number
}

variable "adjustment_type" {
  description = "The adjustment type for the autoscaling policy"
  type        = string
}

variable "policy_type" {
  description = "The policy type for the autoscaling policy"
  type        = string
}

variable "sendgrid_api_key" {
  description = "The SendGrid API key for sending emails"
  type        = string
  sensitive   = true
}
variable "email_from" {
  description = "The email address from which the emails will be sent"
  type        = string
}

variable "launch_template"{
  description = "aws launch template"
  type = string
}

variable "asg"{
  description = "=Auto scaling group"
  type= string
}