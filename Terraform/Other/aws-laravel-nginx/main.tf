provider "aws" {
  region = "us-east-1"
}

# VPC configuration
resource "aws_vpc" "vpc_laravel" {
  cidr_block           = "10.0.1.0/24"
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "vpc_laravel"
  }
}
