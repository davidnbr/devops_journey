### Provider configuration
provider "aws" {
  region = "us-east-1"
}

### VPC configuration
resource "aws_vpc" "vpc_laravel" {
  cidr_block           = "10.0.1.0/24"
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "vpc_laravel"
  }
}

### Subnet configuration
## Public subnet
resource "aws_subnet" "subnet_public_laravel" {
  for_each   = toset(["10.0.1.0/26", "10.0.1.64/26"])
  vpc_id     = aws_vpc.vpc_laravel.id
  cidr_block = each.value
  tags = {
    Name = "subnet_public_laravel_${each.key}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "gateway_internet_laravel" {
  vpc_id = aws_vpc.vpc_laravel.id
  tags = {
    Name = "gateway_internet_laravel"
  }

}

# Route Table
resource "aws_route_table" "route_public_laravel" {
  vpc_id = aws_vpc.vpc_laravel.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gateway_internet_laravel.id
  }
}

# Associate route table
resource "aws_route_table_association" "route_association_public_laravel" {
  for_each       = aws_subnet.subnet_public_laravel
  subnet_id      = each.value.id
  route_table_id = aws_route_table.route_public_laravel.id
}


## Private subnet
resource "aws_subnet" "subnet_private_laravel" {
  for_each                = toset(["10.0.1.128/26", "10.0.1.192/26"])
  vpc_id                  = aws_vpc.vpc_laravel.id
  cidr_block              = each.value
  map_public_ip_on_launch = false

  availability_zone = ["us-east-1a", "us-east-1b"][index(["10.0.100.0/24", "10.0.101.0/24"], each.value)]

  tags = {
    Name = "subnet_private_laravel_${each.key}"
  }
}

# Route Table
resource "aws_route_table" "route_private_laravel" {
  for_each = toset(["10.0.1.128/26", "10.0.1.192/26"])
  vpc_id   = aws_vpc.vpc_laravel.id

  tags = {
    Name = "route_private_laravel_${each.key}"
  }
}

# Associate route table
resource "aws_route_table_association" "route_association_private_laravel" {
  for_each       = aws_subnet.subnet_private_laravel
  subnet_id      = each.value.id
  route_table_id = aws_route_table.route_private_laravel[each.key].id
}
