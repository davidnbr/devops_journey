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

# Subnet configuration
# Public subnet
resource "aws_subnet" "subnet_public_laravel" {
  for_each   = toset(["10.0.1.1/25", "10.0.1.2/25"])
  vpc_id     = aws_vpc.vpc_laravel.id
  cidr_block = each.value
  tags = {
    Name = "subnet_public_laravel_${each.key}"
  }
}

# Private subnet
resource "aws_subnet" "subnet_private_laravel" {
  for_each                = toset(["10.0.1.128/25", "10.0.1.129/25"])
  vpc_id                  = aws_vpc.vpc_laravel.id
  cidr_block              = each.value
  map_public_ip_on_launch = false
  tags = {
    Name = "subnet_private_laravel_${each.key}"
  }
}
