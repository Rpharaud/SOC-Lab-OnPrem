terraform {
  required_version = ">= 1.3.0"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

# Example network for lab containers (adjust as needed)
resource "docker_network" "lab_net" {
  name = "enterprise_lab_net"
  driver = "bridge"
}

# Placeholder container stanza (disabled by default)
# Uncomment and edit when ready to manage services via Terraform.
# resource "docker_container" "arkime" {
#   name  = "arkime-viewer"
#   image = "arkime/arkime:latest"
#   networks_advanced { name = docker_network.lab_net.name }
#   # ports { internal = 8005 external = 8005 }
#   # volumes = ["/opt/arkime/etc:/opt/arkime/etc:ro"]
# }
