# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

# Create a VPC
resource "aws_vpc" "vpc_nginx_training" {
  cidr_block           = "10.0.0.0/16"
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "vpc_nginx_training"
  }
}

# Retrieve availability zones
data "aws_availability_zones" "aws_availablity_zones_data" {
  filter {
    name   = "state"
    values = ["available"]
  }
  filter {
    name   = "region-name"
    values = ["us-east-1"]
  }
  exclude_names = ["us-east-1e"]
}


# Create public subnets
resource "aws_subnet" "public_subnet_nginx_training" {
  for_each          = toset(["10.0.1.0/24", "10.0.2.0/24"])
  vpc_id            = aws_vpc.vpc_nginx_training.id
  cidr_block        = each.value
  availability_zone = data.aws_availability_zones.aws_availablity_zones_data.names[index(["10.0.1.0/24", "10.0.2.0/24"], each.value)]
  tags = {
    Name = "public_subnet_nginx_training"
  }
}

moved {
  from = aws_subnet.public_subnet_nginx_training
  to   = aws_subnet.public_subnet_nginx_training["10.0.1.0/24"]
}

moved {
  from = aws_subnet.public_subnet_nginx_training_2
  to   = aws_subnet.public_subnet_nginx_training["10.0.2.0/24"]
}

# Create private subnets
resource "aws_subnet" "private_subnet_nginx_training" {
  for_each                = toset(["10.0.100.0/24", "10.0.101.0/24"])
  vpc_id                  = aws_vpc.vpc_nginx_training.id
  cidr_block              = each.value
  map_public_ip_on_launch = false
  availability_zone       = ["us-east-1c", "us-east-1d"][index(["10.0.100.0/24", "10.0.101.0/24"], each.value)]

  tags = {
    Name = "private_subnet_nginx_training"
  }
}

moved {
  from = aws_subnet.private_subnet_nginx_training
  to   = aws_subnet.private_subnet_nginx_training["10.0.100.0/24"]
}

moved {
  from = aws_subnet.private_subnet_nginx_training_2
  to   = aws_subnet.private_subnet_nginx_training["10.0.101.0/24"]
}

# Set up gateways

# Create internet gateway (Public)
resource "aws_internet_gateway" "gw_nginx_training" {
  vpc_id = aws_vpc.vpc_nginx_training.id

  tags = {
    Name = "gw_nginx_training"
  }
}

# Create nat gateway (Private)
resource "aws_nat_gateway" "nat_gw_nginx_training" {
  connectivity_type = "private"
  subnet_id         = aws_subnet.private_subnet_nginx_training["10.0.100.0/24"].id
}

# Set up route tables
# Private route table
resource "aws_route_table" "vpc_nginx_route_table_private" {
  vpc_id = aws_vpc.vpc_nginx_training.id

  route {
    cidr_block = "10.0.100.0/24"
    gateway_id = aws_nat_gateway.nat_gw_nginx_training.id
  }

  tags = {
    Name = "vpc_nginx_route_table_private"
  }
}

# Associate the route table with the private subnets
resource "aws_route_table_association" "private_subnet_association" {
  for_each       = aws_subnet.private_subnet_nginx_training
  subnet_id      = each.value.id
  route_table_id = aws_route_table.vpc_nginx_route_table_private.id
}

# Public route table
resource "aws_route_table" "vpc_nginx_route_table_public" {
  vpc_id = aws_vpc.vpc_nginx_training.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw_nginx_training.id
  }

  tags = {
    Name = "vpc_nginx_route_table_public"
  }
}

# Associate the route table with the public subnets
resource "aws_route_table_association" "public_subnet_association" {
  for_each       = aws_subnet.public_subnet_nginx_training
  subnet_id      = each.value.id
  route_table_id = aws_route_table.vpc_nginx_route_table_public.id
}
