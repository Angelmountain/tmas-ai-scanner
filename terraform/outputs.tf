output "app_url" {
  description = "Application URL"
  value       = "https://${var.domain_name}"
}

output "alb_dns" {
  description = "ALB DNS name"
  value       = aws_lb.app.dns_name
}

output "ec2_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.app.id
}

output "ec2_public_ip" {
  description = "EC2 public IP"
  value       = aws_instance.app.public_ip
}

output "certificate_arn" {
  description = "ACM certificate ARN"
  value       = aws_acm_certificate.app.arn
}
