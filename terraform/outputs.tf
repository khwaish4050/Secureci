output "secureci_public_ip" {
  description = "Public IP of the SecureCI instance."
  value       = aws_instance.secureci.public_ip
}

output "secureci_url" {
  description = "URL to access the SecureCI UI/API."
  value       = "http://${aws_instance.secureci.public_ip}:8000"
}

