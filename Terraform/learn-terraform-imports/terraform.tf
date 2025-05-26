# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  cloud {
  }

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.6.0"
    }
  }

  required_version = "~> 1.5"
}
