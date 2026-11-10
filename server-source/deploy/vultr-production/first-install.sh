#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
DEPLOY_DIR=/opt/akfes/app/deploy/vultr-production
cd "$DEPLOY_DIR"

[[ -f /opt/akfes/app/web/index.html && ! -L /opt/akfes/app/web/index.html && -s /opt/akfes/app/web/index.html ]] || {
  echo 'Missing or unsafe web client entry point.' >&2
  exit 1
}
[[ -d /opt/akfes/app/web/assets && ! -L /opt/akfes/app/web/assets ]] || {
  echo 'Missing or unsafe compiled web asset directory.' >&2
  exit 1
}
find /opt/akfes/app/web/assets -xdev -type f -size +0c -print -quit | grep -q . || {
  echo 'Compiled web asset directory is empty.' >&2
  exit 1
}
find /opt/akfes/app/web -xdev -type d -exec chmod 0755 {} +
find /opt/akfes/app/web -xdev -type f -exec chmod 0644 {} +

# Windows archive tooling can preserve CRLF in environment/config files.
# A trailing CR becomes part of an image digest when sourced by Bash and makes
# Docker report "invalid reference format". Normalize text deployment inputs
# before reading any of them. Application source and binary assets are untouched.
find /opt/akfes/app -type f \( -name '*.sh' -o -name '*.env' -o -name '*.example' -o -name '*.yml' -o -name 'Caddyfile' \) \
  -exec sed -i 's/\r$//' {} +

if [[ ! -f .env.production ]]; then
  install -o root -g akfesadmin -m 0640 .env.production.example .env.production
fi

# Arduino is an opt-in secret-chat factor.  Existing deployments created when
# it was an account bootstrap requirement retain that old setting in their
# persistent .env.production, so migrate it explicitly on every safe update.
# Device proof-of-possession remains required independently.
set_config_value() {
  local key="$1" value="$2"
  if grep -q "^${key}=" .env.production; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env.production
  else
    printf '%s=%s\n' "$key" "$value" >> .env.production
  fi
}
set_config_value REQUIRE_FIRST_DEVICE_ARDUINO false
set_config_value ARDUINO_ACTIONS "'[\"device.bootstrap\",\"device.approve\",\"device.revoke\",\"device.revoke_all\",\"arduino.connect\",\"arduino.pin_setup\",\"secret.gate_register\"]'"
chown root:akfesadmin .env.production
chmod 0640 .env.production
chmod 0755 ./*.sh
./install-host-tuning.sh
install -o root -g root -m 0755 "$DEPLOY_DIR/show-registration-invite.sh" /usr/local/sbin/akfes-invite
install -o root -g root -m 0755 "$DEPLOY_DIR/clean-all-test-data.sh" /usr/local/sbin/akfes-clean-test-data
install -o root -g root -m 0755 "$DEPLOY_DIR/akfes-help.sh" /usr/local/sbin/akfes-help

if [[ ! -f /opt/akfes/secrets/production.env ]]; then
  ./generate-production-secrets.sh
else
  echo 'Reusing existing production secrets.'
  ./repair-internal-pki.sh
fi

# Older installations predate administrator MFA. Add exactly one persistent
# encryption key without rotating or printing existing secrets.
if ! grep -q '^ADMIN_MFA_ENCRYPTION_KEY=' /opt/akfes/secrets/production.env; then
  printf 'ADMIN_MFA_ENCRYPTION_KEY=%s\n' "$(openssl rand -hex 32)" >> /opt/akfes/secrets/production.env
  chown root:akfesadmin /opt/akfes/secrets/production.env
  chmod 640 /opt/akfes/secrets/production.env
fi

# Share one unpredictable key across isolated services for pseudonymous
# rate-limit identifiers. Never rotate it implicitly on a normal update.
if ! grep -q '^SECRET_KEY=' /opt/akfes/secrets/production.env; then
  printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> /opt/akfes/secrets/production.env
  chown root:akfesadmin /opt/akfes/secrets/production.env
  chmod 640 /opt/akfes/secrets/production.env
fi

./deploy.sh
./install-caddy-config.sh
./verify-production.sh
./install-backup-timer.sh

echo 'AKFES Vultr production installation passed.'
echo 'Registration invite remains at /opt/akfes/secrets/registration-invite.txt'
echo 'Show it later with: sudo akfes-invite'
