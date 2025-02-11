terraform {
  cloud {
    organization = "Devops_Journey_DB"
    workspaces {
      name = "aws-simple-ec2-nginx"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.52.0"
    }
    ansible = {
      source  = "ansible/ansible"
      version = "1.3.0"
    }
  }
}
