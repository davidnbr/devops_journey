# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "f16a737b7ad77dc126313514c06630466b644b9dbf3d5c94c05ea81f07b7aaf6"
resource "docker_container" "web" {
  env          = []
  image        = docker_image.nginx.image_id
  name         = "hashicorp-learn"
  network_mode = "bridge"
  ports {
    external = 8081
    internal = 80
    ip       = "0.0.0.0"
    protocol = "tcp"
  }
}
