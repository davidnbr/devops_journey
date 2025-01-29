# EC2 instance configuration
# Create security group
resource "aws_security_group" "allow_ssh_http_ec2" {
  name        = "allow_ssh_http_ec2"
  description = "Allow inbound SSH traffic and http from any IP"
  vpc_id      = aws_vpc.vpc_nginx_training.id

  #ssh access
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    # Restrict ingress to necessary IPs/ports.
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP access
  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    # Restrict ingress to necessary IPs/ports.
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all traffic out"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh_http_ec2"
  }
}

# Retrieve most recent instance image
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
resource "aws_instance" "ec2_ssh_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  key_name                    = aws_key_pair.tf_key.key_name
  vpc_security_group_ids      = [aws_security_group.allow_ssh_http_ec2.id]
  associate_public_ip_address = true

  subnet_id = aws_subnet.public_subnet_nginx_training["10.0.1.0/24"].id

  tags = {
    Name = "NodeJS-server"
  }
}

# Create key pair
# RSA key of size 4096 bits
resource "tls_private_key" "rsa_4096_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "tf_key" {
  key_name   = "ec2_key_pair"
  public_key = tls_private_key.rsa_4096_ssh.public_key_openssh
}

# Store private key in a file
resource "local_file" "tf_key" {
  content         = tls_private_key.rsa_4096_ssh.private_key_pem
  filename        = "${path.module}/ec2_key_pair.pem"
  file_permission = 0400
}

resource "aws_eip" "ec2_nginx_eip" {
  instance = aws_instance.ec2_ssh_server.id
  domain   = "vpc"

  depends_on = [aws_internet_gateway.gw_nginx_training]
}


# RDS instance configuration
# Create security group
resource "aws_security_group" "allow_sql_rds" {
  name        = "allow_sql_rds"
  description = "Allow inbound MySQL traffic from any IP"
  vpc_id      = aws_vpc.vpc_nginx_training.id

  # MySQL access
  ingress {
    from_port = 3306
    to_port   = 3306
    protocol  = "tcp"
    # Restrict ingress to necessary IPs/ports.
    security_groups = [aws_security_group.allow_ssh_http_ec2.id]
  }
}

# Subnet RDS group
resource "aws_db_subnet_group" "db_subnet_group_nginx_training" {
  name       = "db_subnet_group_nginx_training"
  subnet_ids = [for subnet in aws_subnet.private_subnet_nginx_training : subnet.id]
}

# Create RDS instance
resource "aws_db_instance" "db_instance_nginx_training" {
  allocated_storage           = 20
  engine                      = "mysql"
  engine_version              = "8.0.39"
  instance_class              = "db.t4g.micro"
  db_name                     = var.db_name
  username                    = var.db_user
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.db_subnet_group_nginx_training.name
  vpc_security_group_ids      = [aws_security_group.allow_sql_rds.id]
  skip_final_snapshot         = true

  tags = {
    Name = "db_instance_nginx_training"
  }
}

### Ansible resources
# Provision EC2 instance
resource "ansible_host" "ansible_host_nginx_training" {
  name   = aws_instance.ec2_ssh_server.public_ip
  groups = ["nginx_training"]

  variables = {
    ansible_user                 = "ubuntu"
    ansible_ssh_private_key_file = "${path.module}/ec2_key_pair.pem"
    ansible_python_interpreter   = "/usr/bin/python3"
  }
}

# Create playbook resource
resource "ansible_playbook" "playbook_nginx_training" {
  playbook   = "${path.module}/ansible/playbook.yml"
  groups     = ["nginx_training"]
  name       = aws_instance.ec2_ssh_server.public_ip
  replayable = true

  extra_vars = {
    ansible_user                 = "ubuntu"
    ansible_ssh_private_key_file = "${path.module}/ec2_key_pair.pem"
    ansible_python_interpreter   = "/usr/bin/python3"
  }
}

