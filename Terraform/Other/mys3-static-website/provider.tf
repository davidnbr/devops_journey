terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = "5.10.0"
        }
    }
}

provider "aws" {
    # Configuration options
    # For SSO Login
    shared_config_files = ["$HOME/.aws/config"]
    profile = "admin-1"
    region = "us-east-1"
}