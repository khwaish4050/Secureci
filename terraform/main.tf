data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_vpc" "default" {
  default = true
}

locals {
  use_managed_keypair = length(trimspace(var.public_key_path)) > 0
  effective_key_name  = local.use_managed_keypair ? "secureci-key" : trimspace(var.key_name)
}

resource "aws_key_pair" "secureci" {
  count      = local.use_managed_keypair ? 1 : 0
  key_name   = local.effective_key_name
  public_key = file(var.public_key_path)

  tags = {
    Name = "secureci-key"
  }
}

resource "aws_security_group" "secureci" {
  name        = "secureci-sg"
  description = "SecureCI demo instance security group"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description = "SecureCI API/UI"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_app_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "secureci-sg"
  }
}

resource "aws_instance" "secureci" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = local.use_managed_keypair ? aws_key_pair.secureci[0].key_name : local.effective_key_name
  vpc_security_group_ids = [aws_security_group.secureci.id]

  user_data = <<-EOF
    #!/bin/bash
    set -euxo pipefail

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends git ca-certificates curl docker.io docker-compose
    systemctl enable --now docker

    mkdir -p /opt/secureci
    cd /opt/secureci

    if [ ! -d repo ]; then
      git clone --depth 1 ${var.secureci_repo_url} repo
    fi
    cd repo
    git fetch --depth 1 origin ${var.secureci_repo_ref}
    git checkout ${var.secureci_repo_ref}

    # Start SecureCI (FastAPI + dashboard) on port 8000.
    docker-compose up -d
  EOF

  user_data_replace_on_change = true

  tags = {
    Name = "secureci"
  }
}
