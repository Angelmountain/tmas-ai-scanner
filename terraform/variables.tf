variable "aws_region" {
  description = "AWS region for deployment"
  default     = "eu-north-1"
}

variable "domain_name" {
  description = "Subdomain for the platform"
  default     = "secassess.nordicnetintruders.com"
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for nordicnetintruders.com"
  default     = "Z05323043AEFFK0DYL2D0"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "t3.medium"
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to access the platform"
  type        = list(string)
  default     = ["162.120.188.91/32", "162.120.188.0/24", "94.254.60.123/32"]
}

variable "admin_cidr" {
  description = "CIDR block allowed for SSH access"
  default     = "162.120.188.0/24"
}

variable "ssh_key_name" {
  description = "Name of existing EC2 key pair for SSH (leave empty to skip)"
  default     = ""
}

variable "github_repo" {
  description = "GitHub repository to clone"
  default     = "https://github.com/Angelmountain/tmas-ai-scanner.git"
}
