$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$tfDir = Join-Path $repoRoot "terraform"
$inventoryPath = Join-Path $PSScriptRoot "inventory.ini"
$sshKey = Join-Path $env:USERPROFILE ".ssh\\secureci_ed25519"

if (!(Test-Path $sshKey)) {
  throw "SSH private key not found at $sshKey. It should exist if you used the Terraform keypair flow."
}

if (!(Test-Path $tfDir)) {
  throw "Terraform directory not found at $tfDir"
}

Push-Location $tfDir
try {
  $ip = (terraform output -raw secureci_public_ip).Trim()
  if (!$ip) { throw "Could not read secureci_public_ip from terraform outputs." }
} finally {
  Pop-Location
}

$inv = @"
[secureci]
secureci-ec2 ansible_host=$ip ansible_user=ubuntu
"@
$inv | Set-Content -Path $inventoryPath -Encoding ASCII

Write-Host "Inventory updated: $inventoryPath"
Write-Host "Target IP: $ip"

# Run Ansible in Docker (so you don't need to install Ansible on Windows).
# Uses your local SSH key to connect to the instance.
$image = "secureci-ansible:latest"

$oldEap = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
docker image inspect $image *> $null
$inspectExit = $LASTEXITCODE
$ErrorActionPreference = $oldEap

if ($inspectExit -ne 0) {
  Write-Host "Building $image (one-time)..."
  docker build -t $image -f (Join-Path $PSScriptRoot "Dockerfile") $repoRoot
}

docker run --rm -t `
  -e ANSIBLE_HOST_KEY_CHECKING=False `
  -v "${repoRoot}:/work" `
  -v "${sshKey}:/tmp/id_ed25519:ro" `
  -w /work/ansible `
  $image `
  sh -lc "mkdir -p /root/.ssh && cp /tmp/id_ed25519 /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519 && ansible-playbook -i inventory.ini site.yml"
