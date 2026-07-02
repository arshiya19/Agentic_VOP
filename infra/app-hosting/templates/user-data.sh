#!/bin/bash
set -euo pipefail

# ==============================================================================
# EC2 Bootstrap Script (user-data)
# Installs dependencies, clones repo, injects secrets, and starts the app stack.
# Template variables: aws_region, env, github_repository
# Version: 2026-07-02-v2
# ==============================================================================

LOG_FILE="/var/log/user-data.log"

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $${1}"
  echo "$${msg}" | tee -a "$${LOG_FILE}"
}

fail() {
  local step="$${1}"
  local err="$${2:-unknown error}"
  log "FATAL: Step '$${step}' failed — $${err}"
  exit 1
}

run_step() {
  local step_name="$${1}"
  shift
  log "START: $${step_name}"
  if "$@" >> "$${LOG_FILE}" 2>&1; then
    log "DONE: $${step_name}"
  else
    fail "$${step_name}" "exit code $?"
  fi
}

# ==============================================================================
# Step 1: Install AWS CLI v2 (ARM64)
# ==============================================================================
install_awscli() {
  apt-get update -y
  apt-get install -y unzip curl
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip
  unzip -qo /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
  aws --version
}
run_step "Install AWS CLI v2" install_awscli

# ==============================================================================
# Step 2: Install Docker Engine + Docker Compose plugin
# ==============================================================================
install_docker() {
  apt-get install -y ca-certificates gnupg lsb-release

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  local arch
  arch=$(dpkg --print-architecture)
  local codename
  codename=$(lsb_release -cs)
  echo "deb [arch=$${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $${codename} stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  systemctl enable docker
  systemctl start docker
  docker --version
  docker compose version
}
run_step "Install Docker Engine + Compose" install_docker

# ==============================================================================
# Step 3: Clone repository
# ==============================================================================
clone_repository() {
  apt-get install -y git
  git clone "https://github.com/${github_repository}.git" /opt/app
  chown -R ubuntu:ubuntu /opt/app
}
run_step "Clone repository" clone_repository

# ==============================================================================
# Step 3.1: Grant ubuntu user access to Docker
# ==============================================================================
grant_docker_access() {
  usermod -aG docker ubuntu
}
run_step "Grant ubuntu Docker access" grant_docker_access

# ==============================================================================
# Step 4: Fetch secrets from SSM Parameter Store and write .env
# ==============================================================================
fetch_secrets() {
  local ssm_path="/sisyfix/${env}/app/"
  local env_file="/opt/app/.env"

  aws ssm get-parameters-by-path \
    --path "$${ssm_path}" \
    --recursive \
    --with-decryption \
    --region "${aws_region}" \
    --query "Parameters[*].[Name,Value]" \
    --output text | while IFS=$'\t' read -r name value; do
      # Extract the key name from the full path (e.g. /sisyfix/prod/app/MY_KEY -> MY_KEY)
      local key="$${name##*/}"
      echo "$${key}=$${value}" >> "$${env_file}"
    done

  chmod 0600 "$${env_file}"
}
run_step "Fetch secrets from SSM" fetch_secrets

# ==============================================================================
# Step 5: Validate required secrets (30s timeout)
# ==============================================================================
validate_secrets() {
  local env_file="/opt/app/.env"
  local required_keys="AGENTIC_VOP_SUPABASE_URL AGENTIC_VOP_SUPABASE_SERVICE_KEY OPENAI_API_KEY SECRETS_ENCRYPTION_KEY"
  local timeout=30
  local elapsed=0
  local interval=5

  while [ "$${elapsed}" -lt "$${timeout}" ]; do
    local missing=""
    for key in $${required_keys}; do
      if ! grep -q "^$${key}=" "$${env_file}" 2>/dev/null; then
        missing="$${missing} $${key}"
      fi
    done

    if [ -z "$${missing}" ]; then
      log "All required secrets validated successfully"
      return 0
    fi

    log "Waiting for required secrets (elapsed: $${elapsed}s, missing:$${missing})"
    sleep "$${interval}"
    elapsed=$((elapsed + interval))
  done

  fail "Validate required secrets" "Missing required secrets after $${timeout}s:$${missing}"
}
run_step "Validate required secrets" validate_secrets

# ==============================================================================
# Step 6: Start Docker Compose stack
# ==============================================================================
start_app() {
  cd /opt/app
  docker compose up -d --build
}
run_step "Docker Compose up" start_app

# ==============================================================================
# Step 7: Write bootstrap completion marker
# ==============================================================================
write_marker() {
  echo "Bootstrap completed at $(date -u '+%Y-%m-%dT%H:%M:%SZ')" > /opt/app/BOOTSTRAP_COMPLETE
}
run_step "Write BOOTSTRAP_COMPLETE marker" write_marker

log "=== EC2 bootstrap finished successfully ==="
