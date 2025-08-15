terraform {
  cloud {
    organization = "Devops_Journey_DB"
    workspaces {
      name = "aws-laravel-nginx"
    }
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100.0"
    }
  }
}
