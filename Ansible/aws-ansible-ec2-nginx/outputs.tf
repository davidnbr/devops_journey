output "ec2_instance_public_ip" {
  value = aws_instance.ec2_ssh_server.public_ip
}

output "ec2_instance_private_ip" {
  value = aws_instance.ec2_ssh_server.private_ip

}

output "public_key" {
  value = aws_key_pair.tf_key.public_key
}

output "web_public_ip" {
  description = "Public IP from eip"
  value       = aws_eip.ec2_nginx_eip.public_ip
  depends_on  = [aws_eip.ec2_nginx_eip]
}

output "web_public_dns" {
  description = "Public DNS address of web server"
  value       = aws_eip.ec2_nginx_eip.public_dns
  depends_on  = [aws_eip.ec2_nginx_eip]
}

output "db_address" {
  description = "Database address"
  value       = aws_db_instance.db_instance_nginx_training.address
}

output "db_port" {
  description = "Database port"
  value       = aws_db_instance.db_instance_nginx_training.port
}

## Ansible outputs
output "ansible_stderr" {
  description = "Ansible stderr"
  value       = ansible_playbook.playbook_nginx_training.ansible_playbook_stderr
}


output "ansible_stdout" {
  description = "Ansible stdout"
  value       = ansible_playbook.playbook_nginx_training.ansible_playbook_stdout
}
