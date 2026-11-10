#!/usr/bin/env bash
set -euo pipefail

cd /opt/akfes/app/deploy/vultr-production
set -a
source <(sed 's/\r$//' .env.production)
source <(sed 's/\r$//' /opt/akfes/secrets/production.env)
source <(sed 's/\r$//' /opt/akfes/app/release/docker-image-digests.env)
set +a

docker compose ps
wait_http(){
  local label="$1" url="$2" attempt response
  for attempt in $(seq 1 60); do
    if response="$(curl --fail --silent --show-error --max-time 5 "$url" 2>/dev/null)"; then
      echo "PASS: ${label}: ${response}"
      return 0
    fi
    sleep 2
  done
  echo "FAIL: ${label}: ${url}" >&2
  return 1
}
wait_http API-LIVE http://127.0.0.1:18001/health/live
wait_http API-READY http://127.0.0.1:18001/health/ready
wait_http REALTIME-READY http://127.0.0.1:18002/health/ready
wait_http AUTH-READY http://127.0.0.1:18003/health/ready
wait_http HTTPS-READY https://api.akfes.pe.kr/health/ready

web_url=https://api.akfes.pe.kr/
web_html="$(curl --silent --show-error --max-time 10 --write-out $'\n%{http_code}' "$web_url")" || {
  curl_exit=$?
  echo "FAIL: web request could not complete (curl exit ${curl_exit}): $web_url" >&2
  exit 1
}
web_status="${web_html##*$'\n'}"
web_html="${web_html%$'\n'*}"
if [[ "$web_status" != 200 ]]; then
  echo "FAIL: web client returned HTTP ${web_status}: $web_url" >&2
  curl --silent --show-error --max-time 10 -i "$web_url" 2>&1 | sed -n '1,30p' >&2 || true
  echo 'Static web path diagnostics:' >&2
  namei -l /var/www/akfes/index.html >&2 || true
  exit 1
fi
grep -q '<title>AKFES Secure Messenger</title>' <<<"$web_html" || { echo 'FAIL: web client title is missing.' >&2; exit 1; }
web_headers="$(curl --silent --show-error --max-time 10 -D - -o /dev/null "$web_url")" || {
  echo "FAIL: web response headers could not be read: $web_url" >&2
  exit 1
}
grep -qi '^content-security-policy:' <<<"$web_headers" || { echo 'FAIL: web Content-Security-Policy is missing.' >&2; exit 1; }
grep -qi '^strict-transport-security:' <<<"$web_headers" || { echo 'FAIL: web HSTS is missing.' >&2; exit 1; }
grep -qi '^permissions-policy:.*display-capture=()' <<<"$web_headers" || { echo 'FAIL: web display-capture policy is missing.' >&2; exit 1; }
grep -qi '^permissions-policy:.*camera=(self)' <<<"$web_headers" || { echo 'FAIL: web camera policy is missing.' >&2; exit 1; }
grep -qi '^permissions-policy:.*microphone=(self)' <<<"$web_headers" || { echo 'FAIL: web microphone policy is missing.' >&2; exit 1; }
echo 'PASS: HTTPS web client and security headers.'

conversation_constraint="$(docker compose exec -T db psql -X -At -v ON_ERROR_STOP=1 -U akfes_api -d akfes -c "SELECT count(*) FROM pg_constraint WHERE conname='ck_conversations_status'")"
[[ "$conversation_constraint" == '1' ]] || { echo 'FAIL: conversation state constraint is missing.' >&2; exit 1; }
invalid_conversations="$(docker compose exec -T db psql -X -At -v ON_ERROR_STOP=1 -U akfes_api -d akfes -c "SELECT count(*) FROM conversations WHERE status NOT IN ('pending','accepted','rejected','blocked')")"
[[ "$invalid_conversations" == '0' ]] || { echo "FAIL: invalid conversation security states: $invalid_conversations" >&2; exit 1; }
social_tables="$(docker compose exec -T db psql -X -At -v ON_ERROR_STOP=1 -U akfes_api -d akfes -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('friendships','community_servers','community_server_members')")"
[[ "$social_tables" == '3' ]] || { echo 'FAIL: friend/group/server schema is incomplete.' >&2; exit 1; }
echo 'PASS: conversation state policy is enforced by the database.'

public="$(ss -lntH | awk '{print $4}' | grep -E '(^|:)(5432|6379|6380|18001|18002|18003)$' | grep -vE '^127\.0\.0\.1:' || true)"
[[ -z "$public" ]] || { echo "FAIL: internal port exposed: $public" >&2; exit 1; }
echo 'PASS: Vultr production health, HTTPS, and port isolation checks passed.'
