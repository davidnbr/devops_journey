### EC2 instances
# Security group
resource "aws_security_group" "sec_grp_ec2_allow_ssh_http" {
  name        = "sec_grp_ec2_allow_ssh_http"
  description = "Allow SSH and HTTP inbound traffic"
  vpc_id      = aws_vpc.vpc_laravel.id

  # SSH port
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP port
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Name = "sec_grp_ec2_allow_ssh_http"
  }
}

# AMI data source
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical

}

# Create instance
resource "aws_instance" "ec2_laravel" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  key_name                    = aws_key_pair.tf_key.key_name
  vpc_security_group_ids      = [aws_security_group.sec_grp_ec2_allow_ssh_http.id]
  associate_public_ip_address = true

  subnet_id = aws_subnet.subnet_public_laravel["10.0.1.0/26"].id

  tags = {
    Name = "ec2_laravel"
  }

  depends_on = [aws_security_group.sec_grp_ec2_allow_ssh_http]

}

# Create key pair
# RSA key of size 4096 bits
resource "tls_private_key" "key_rsa_4096" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Store private key in a file
resource "local_file" "tf_key" {
  content         = tls_private_key.key_rsa_4096.private_key_pem
  filename        = "${path.module}/ec2_key_pair.pem"
  file_permission = 0400
}

resource "aws_key_pair" "tf_key" {
  key_name   = "ec2_key_pair"
  public_key = tls_private_key.key_rsa_4096.public_key_openssh
}

### RDS instances
# Create security group
resource "aws_security_group" "sec_grp_rds_allow_mysql" {
  name        = "sec_grp_rds_allow_mysql"
  description = "Allow MySQL inbound traffic"
  vpc_id      = aws_vpc.vpc_laravel.id

  # MySQL port
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_security_group.sec_grp_ec2_allow_ssh_http.id]
    # From
    security_groups = [aws_security_group.sec_grp_ec2_allow_ssh_http.id]
  }
}

# Create subnet RDS group
resource "aws_db_subnet_group" "db_subnet_group_laravel" {
  name       = "db_subnet_group_laravel"
  subnet_ids = [for subnet in subnet_private_laravel : subnet.id]
  depends_on = [aws_route_table_association.route_association_private_laravel]
}
