#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/akfes/app
DEPLOY_DIR="$APP_DIR/deploy/vultr-production"
SECRET_ENV=/opt/akfes/secrets/production.env
DIGEST_ENV="$APP_DIR/release/docker-image-digests.env"
CONFIG_ENV="$DEPLOY_DIR/.env.production"

for file in "$SECRET_ENV" "$DIGEST_ENV" "$CONFIG_ENV"; do
  [[ -f "$file" ]] || { echo "Missing required file: $file" >&2; exit 1; }
done
set -a
source <(sed 's/\r$//' "$CONFIG_ENV")
source <(sed 's/\r$//' "$SECRET_ENV")
source <(sed 's/\r$//' "$DIGEST_ENV")
set +a

[[ "${AKFES_DOMAIN:-}" == 'api.akfes.pe.kr' ]] || { echo 'Unexpected AKFES_DOMAIN' >&2; exit 1; }
mkdir -p /opt/akfes/data/{postgres,files,security-redis,realtime-redis} /opt/akfes/backups
chmod 750 /opt/akfes/data /opt/akfes/backups

cd "$DEPLOY_DIR"
docker compose config --quiet
docker compose pull db security-redis realtime-redis grants
docker compose build --pull api auth
if [[ -f /opt/akfes/secrets/.pki-rotated ]]; then
  # Every TLS peer must restart together because the internal CA changed.
  docker compose up -d --remove-orphans --force-recreate
  rm -f /opt/akfes/secrets/.pki-rotated
else
  docker compose up -d --remove-orphans
fi
docker compose ps

wait_http(){
  local label="$1" url="$2" attempt response
  for attempt in $(seq 1 60); do
    if response="$(curl --fail --silent --show-error --max-time 5 "$url" 2>/dev/null)"; then
      echo "PASS: ${label} ready: ${response}"
      return 0
    fi
    sleep 2
  done
  echo "FAIL: ${label} did not become ready: ${url}" >&2
  return 1
}

wait_http API http://127.0.0.1:18001/health/ready
wait_http AUTH http://127.0.0.1:18003/health/ready

if ss -lnt | grep -Eq '0\.0\.0\.0:(18001|18003|5432|6379|6380)'; then
  echo 'FAIL: an internal AKFES port is publicly bound' >&2
  exit 1
fi
echo 'PASS: AKFES containers are healthy and internal ports are not public.'
