variable "aws_region" {
  type        = string
  description = "AWS region to deploy into."
  default     = "us-east-1"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type."
  default     = "t3.micro"
}

variable "key_name" {
  type        = string
  description = "Existing EC2 key pair name for SSH access (leave empty if using public_key_path)."
  default     = ""
}

variable "public_key_path" {
  type        = string
  description = "Path to an SSH public key (.pub). If set, Terraform will create/import an EC2 key pair automatically."
  default     = ""
}

variable "allowed_ssh_cidr" {
  type        = string
  description = "CIDR allowed to SSH to the instance."
  default     = "0.0.0.0/0"
}

variable "allowed_app_cidr" {
  type        = string
  description = "CIDR allowed to access SecureCI on port 8000."
  default     = "0.0.0.0/0"
}

variable "secureci_repo_url" {
  type        = string
  description = "Git repo URL to deploy on the instance."
  default     = "https://github.com/khwaish4050/Secureci.git"
}

variable "secureci_repo_ref" {
  type        = string
  description = "Git ref (branch/tag/sha) to deploy."
  default     = "main"
}
