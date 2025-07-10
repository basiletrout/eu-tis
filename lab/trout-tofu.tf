terraform {
  required_providers {
    incus = {
      source  = "lxc/incus"
      version = "0.2.0"
    }
  }
}

provider "incus" {}

# WAN Network #

resource "incus_network" "wan" {
  name = "incus-wan"
  type = "bridge"

  config = {
    "ipv4.dhcp" = "true"
    "ipv4.address" = "198.18.100.1/24"
    "ipv4.nat"     = "true"
    "ipv6.nat" = "true"
  }
}


# Access-Gate (TROUT) #

resource "incus_instance" "trout" {
  name    = "Trout-machine"
  type    = "virtual-machine"
  image   = "local:trout"
  running = true

  config = {
    "security.secureboot" = "false"

  }
  device {
    name = "eth0"
    type = "nic"

    properties = {
      network = incus_network.wan.name
      type    = "nic"
    }
  }
}