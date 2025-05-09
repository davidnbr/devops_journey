terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = "5.10.0"
        }
        time = {
            source = "hashicorp/time"
            version = "~> 0.13.0"
        }
    }
}

provider "aws" {
    # Configuration options
    # For SSO Login
    shared_config_files = var.aws_shared_config_files
    profile = var.aws_profile
    region = var.aws_region
}