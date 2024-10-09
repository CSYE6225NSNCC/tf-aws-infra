terraform {
  required_version = ">= 1.0.0" # Change to your required version

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0" # Change to your required provider version
    }
  }
}
