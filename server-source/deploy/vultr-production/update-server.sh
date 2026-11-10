#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ -f /opt/akfes/secrets/production.env ]] || { echo 'Production secrets are missing; run first-install.sh.' >&2; exit 1; }
[[ -f /opt/akfes/app/deploy/vultr-production/.env.production ]] || { echo 'Production config is missing.' >&2; exit 1; }

cd /opt/akfes/app/deploy/vultr-production
./backup.sh
./deploy.sh
./install-caddy-config.sh
./verify-production.sh
echo 'AKFES server update passed; data and secrets were preserved.'
