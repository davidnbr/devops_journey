output "ec2_instance_public_ip" {
  value = aws_instance.ec2_laravel.public_ip
}

output "ec2_instance_private_ip" {
  value = aws_instance.ec2_laravel.private_ip
}

output "rsa_public_key" {
  value = aws_key_pair.tf_key.public_key
}
