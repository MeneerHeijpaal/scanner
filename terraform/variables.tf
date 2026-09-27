variable "hcloud_token" {
  description = "Hetzner Cloud API token. Set in terraform.tfvars (gitignored)."
  type        = string
  sensitive   = true
}

variable "worker_count" {
  description = "Number of scanner worker VPSes to spread the scan load across."
  type        = number
  default     = 3
}

variable "server_type" {
  description = "Hetzner server type (e.g. cx22, cpx21, cpx31)."
  type        = string
  default     = "cx22"
}

variable "location" {
  description = "Hetzner location (nbg1, fsn1, hel1, ash, hil)."
  type        = string
  default     = "nbg1"
}

variable "image" {
  description = "Base OS image."
  type        = string
  default     = "ubuntu-24.04"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key uploaded to Hetzner and used for access."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "ssh_admin_cidrs" {
  description = "CIDRs allowed to reach the workers over SSH (lock this down)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "repo_url" {
  description = "Git URL of this repository, cloned onto each worker by cloud-init."
  type        = string
  default     = "https://github.com/MeneerHeijpaal/scanner.git"
}

variable "es_endpoint" {
  description = "Central Elasticsearch endpoint the workers ingest into (host:port)."
  type        = string
  default     = ""
}

variable "interactsh_server" {
  description = "Interactsh server URL used by nuclei on the workers."
  type        = string
  default     = "example.com"
}

variable "labels" {
  description = "Extra labels applied to every worker."
  type        = map(string)
  default     = {}
}
