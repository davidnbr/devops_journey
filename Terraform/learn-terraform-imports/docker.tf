# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Terraform configuration
import {
  id = "f16a737b7ad77dc126313514c06630466b644b9dbf3d5c94c05ea81f07b7aaf6"
  to = docker_container.web
}

resource "docker_image" "nginx" {
  name = "nginx:latest"
}
