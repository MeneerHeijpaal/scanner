# Distribute the scanning load across multiple Hetzner Cloud VPSes.
#
# Each worker is provisioned identically via cloud-init: it installs the
# ProjectDiscovery tools (httpx, naabu, nuclei), clones this repository, and is
# pointed at a central Elasticsearch endpoint and the Interactsh server. Targets
# are sharded across the workers with Python/distribute_targets.py.

# SSH key uploaded to the Hetzner project and injected into each worker.
resource "hcloud_ssh_key" "scanner" {
  name       = "scanner-key"
  public_key = file(var.ssh_public_key_path)
}

# Firewall: SSH from the admin CIDRs only; allow all egress for scanning.
resource "hcloud_firewall" "scanner" {
  name = "scanner-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.ssh_admin_cidrs
  }

  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction       = "out"
    protocol        = "icmp"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }
}

# The scanner worker VPSes.
resource "hcloud_server" "worker" {
  count       = var.worker_count
  name        = "scanner-worker-${count.index + 1}"
  server_type = var.server_type
  image       = var.image
  location    = var.location
  ssh_keys    = [hcloud_ssh_key.scanner.id]
  firewall_ids = [hcloud_firewall.scanner.id]

  labels = merge({
    role  = "scanner-worker"
    stack = "scanner"
  }, var.labels)

  user_data = templatefile("${path.module}/cloud-init.yaml", {
    repo_url          = var.repo_url
    es_endpoint       = var.es_endpoint
    interactsh_server = var.interactsh_server
    worker_index      = count.index + 1
    worker_count      = var.worker_count
  })
}
