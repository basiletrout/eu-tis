terraform {
  required_providers {
    incus = {
      source  = "lxc/incus"
      version = "0.2.0"
    }
  }
}

provider "incus" {}

### NETWORKS ###

# WAN Network (For Attacker) #
resource "incus_network" "wan" {
  name = "incus-wan"
  type = "bridge"

  config = {
    "ipv4.dhcp"     = "true"   
    "ipv4.address"  = "198.18.100.1/24"
    "ipv4.nat"      = "true"
    "ipv6.nat"      = "true"
    "security.acls" = incus_network_acl.isolation.name
  }
}

# LAN Network (For Targets) #
resource "incus_network" "lan" {
  name = "incus-lan"
  type = "bridge"

  config = {
    "ipv4.dhcp"     = "false" 
    "ipv4.address"  = "198.18.200.1/24"
    "ipv4.nat"      = "true"
    "ipv6.address"  = "none"
    "security.acls" = incus_network_acl.isolation.name
  }
}

# ACL pour isolation WAN/LAN
resource "incus_network_acl" "isolation" {
  name        = "isolation-acl"
  description = "Isolation between WAN and LAN"

  # Rules EGRESS
  egress = [
    {
      action      = "drop"
      state       = "enabled"
      source      = "198.18.100.0/24"
      destination = "198.18.200.0/24"
      description = "Block WAN to LAN traffic"
    },
    {
      action      = "drop"
      state       = "enabled"
      source      = "198.18.200.0/24"
      destination = "198.18.100.0/24"
      description = "Block LAN to WAN traffic"
    },
    {
      action      = "allow"
      state       = "enabled"
      description = "Allow all other egress traffic (Internet)"
    }
  ]

  # Rules INGRESS 
  ingress = [
    {
      action      = "allow"
      state       = "enabled"
      description = "Allow all ingress traffic"
    }
  ]
}

### INSTANCES ###

# Router Container 
resource "incus_instance" "router" {
  name    = "Router-Firewall"
  image   = "images:debian/13/cloud"
  running = true

  config = {
    "user.user-data" = <<EOF
#cloud-config
packages:
  - ifupdown
  - dnsmasq

write_files:
  - path: /etc/dnsmasq.conf
    content: |
      interface=eth1
      bind-interfaces
      dhcp-broadcast
      dhcp-range=198.18.200.50,198.18.200.100,12h
      domain-needed
      bogus-priv
      no-resolv
      log-queries
      log-dhcp
      server=8.8.8.8
      server=8.8.4.4

  - path: /etc/network/interfaces
    content: |
      auto eth1
      iface eth1 inet static
      address 198.18.200.10
      netmask 255.255.255.0
      gateway 198.18.200.1

  - path: /etc/sysctl.conf
    content: |
      net.ipv4.ip_forward=0

runcmd:
  - ip link set eth1 up
  - sleep 5
  - systemctl restart networking
  - systemctl restart dnsmasq
EOF
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.wan.name
    }
  }

  device {
    name = "eth1"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }
}

# Attacker (WAN) #
resource "incus_instance" "attacker" {
  name    = "Attacker"
  image   = "images:kali/current/default"
  running = true

  config = {
    "limits.cpu"    = "4"
    "limits.memory" = "8GiB"
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.wan.name
    }
  }


}

# DVWA (LAN) #
resource "incus_instance" "dvwa" {
  name    = "DVWA"
  image   = "images:debian/13/cloud"
  type    = "container"
  running = true

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  config = {
    "user.user-data" = <<EOF
#cloud-config
package_update: true
packages:
  - apache2
  - mariadb-server
  - php
  - php-mysqli
  - wget
  - unzip

bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  # Configuration DVWA
  - systemctl enable apache2 mariadb
  - systemctl start apache2 mariadb
  - mysql -e "CREATE DATABASE dvwa; CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd'; GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';"
  - wget -O /tmp/dvwa.zip https://github.com/digininja/DVWA/archive/refs/heads/master.zip
  - unzip /tmp/dvwa.zip -d /var/www/html/
  - mv /var/www/html/DVWA-master /var/www/html/dvwa
  - chown -R www-data:www-data /var/www/html/dvwa
EOF
  }
}

# Target (LAN) #
resource "incus_instance" "target" {
  name    = "Target"
  image   = "images:ubuntu/22.04/cloud"
  type    = "container"
  running = true

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  config = {
    "user.user-data" = <<EOF
#cloud-config
bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  - dhclient eth0
EOF
  }
}

# Windows VM (LAN) #
resource "incus_instance" "windows" {
  name   = "Windows"
  type   = "virtual-machine"
  running = true
  profiles = ["default"]
  wait_for_network = false

  source_instance = {
    name     = "windows-template"
    project  = "default"
    snapshot = "winclient-template"
  }

  config = {
    "limits.cpu"    = "4"
    "limits.memory" = "6GiB"
    "raw.qemu"      = "-device intel-hda -device hda-duplex -audio spice"
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = "incus-storage"
      size = "55GiB"
    }
  }

  device {
    name = "vtpm"
    type = "tpm"
    properties = {
      path = "/dev/tpm0"
    }
  }
}
