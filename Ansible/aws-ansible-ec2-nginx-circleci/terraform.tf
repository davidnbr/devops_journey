terraform {
  cloud {}

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
