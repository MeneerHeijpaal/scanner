output "worker_ips" {
  description = "Public IPv4 addresses of the scanner workers."
  value       = [for s in hcloud_server.worker : s.ipv4_address]
}

output "worker_names" {
  description = "Names of the scanner workers."
  value       = [for s in hcloud_server.worker : s.name]
}

output "worker_ssh" {
  description = "Ready-to-use SSH commands for each worker."
  value       = [for s in hcloud_server.worker : "ssh root@${s.ipv4_address}"]
}
