# =============================================================================
# Lab Instance Module — Outputs
# =============================================================================

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.lab.id
}

output "instance_public_ip" {
  description = "Public IP of the lab instance"
  value       = aws_instance.lab.public_ip
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.lab.id
}

output "ssh_command" {
  description = "SSH command to connect to the lab instance"
  value       = "ssh -i ${var.name_prefix}-key.pem ubuntu@${aws_instance.lab.public_ip}"
}

output "ssh_private_key_path" {
  description = "Path to the generated SSH private key"
  value       = local_file.private_key.filename
}
