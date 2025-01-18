terraform {
    cloud {
        organization = "Devops_Journey_DB"
        workspaces {
            name = "learn-terraform-aws"
        }
    }

    required_providers {
        aws = {
        source  = "hashicorp/aws"
        version = "~> 4.16"
        }
    }

    required_version = ">= 1.2.0"
}

# Deploy made with HCP so ENV variables are specified there
provider "aws" {
    #shared_config_files = ["$HOME/.aws/config"]
    #profile = "admin-1"
    region  = "us-west-2"
}

resource "aws_instance" "app_server" {
    ami           = "ami-08d70e59c07c61a3a"
    instance_type = "t2.micro"
}
