#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---preview}"
ROOT=/opt/akfes
APP_ROOT="$ROOT/app"
COMPOSE_DIR="$APP_ROOT/deploy/vultr-production"
LOCK_FILE=/run/lock/akfes-test-data-cleanup.lock

if [[ "$MODE" != "--preview" && "$MODE" != "--execute" ]]; then
  echo "Usage: $0 [--preview|--execute]" >&2
  exit 2
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo 'Run this script as root (sudo).' >&2
  exit 1
fi

for command in docker flock realpath stat tar sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "Missing required command: $command" >&2; exit 1; }
done

exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'Another AKFES cleanup is already running.' >&2; exit 1; }

[[ "$(realpath -e -- "$ROOT")" == /opt/akfes ]] || { echo 'Unexpected AKFES root.' >&2; exit 1; }
[[ -d "$COMPOSE_DIR" && ! -L "$COMPOSE_DIR" ]] || { echo 'Invalid production compose directory.' >&2; exit 1; }

cd "$COMPOSE_DIR"
[[ -f .env.production && ! -L .env.production ]] || { echo 'Missing production environment file.' >&2; exit 1; }
set -a
# The API sees this mount at /app/encrypted-files, but the cleanup command
# runs on the host. Always derive the host side of the mount from the same
# Compose setting instead of ever inspecting the container-only path.
source <(sed 's/\r$//' .env.production)
set +a
DATA_ROOT="${AKFES_DATA_DIR:-}"
[[ -n "$DATA_ROOT" ]] || { echo 'AKFES_DATA_DIR is missing from production configuration.' >&2; exit 1; }
DATA_ROOT="$(realpath -e -- "$DATA_ROOT")"
case "$DATA_ROOT" in
  /opt/akfes/data) ;;
  *) echo "Unexpected AKFES data root: $DATA_ROOT" >&2; exit 1 ;;
esac
FILES_DIR="$DATA_ROOT/files"
[[ -d "$FILES_DIR" && ! -L "$FILES_DIR" ]] || { echo "Invalid encrypted-file host directory: $FILES_DIR" >&2; exit 1; }
[[ -f "$ROOT/secrets/production.env" && ! -L "$ROOT/secrets/production.env" ]] || { echo 'Missing production secrets.' >&2; exit 1; }
[[ -f "$APP_ROOT/release/docker-image-digests.env" && ! -L "$APP_ROOT/release/docker-image-digests.env" ]] || { echo 'Missing immutable image manifest.' >&2; exit 1; }

set -a
# shellcheck disable=SC1091
source <(sed 's/\r$//' "$ROOT/secrets/production.env")
# shellcheck disable=SC1091
source <(sed 's/\r$//' "$APP_ROOT/release/docker-image-digests.env")
set +a

db_psql() {
  docker compose exec -T db sh -ec '
    export PGPASSWORD="$POSTGRES_API_PASSWORD"
    exec psql -X -v ON_ERROR_STOP=1 -U akfes_api -d akfes "$@"
  ' sh "$@"
}

db_running="$(docker inspect --format '{{.State.Running}}' akfes-production-db-1 2>/dev/null || true)"
[[ "$db_running" == true ]] || { echo 'AKFES database container is not running.' >&2; exit 1; }

allowed_tables_sql="'admin_mfa','admin_passkeys','alembic_version','arduino_grants','attachments','community_server_members','community_servers','conversation_members','conversations','devices','encrypted_files','friendships','messages','prekey_claim_leases','prekeys','security_audit_events','sessions','users'"
unknown_tables="$(db_psql -Atqc "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN ($allowed_tables_sql) ORDER BY tablename")"
if [[ -n "$unknown_tables" ]]; then
  echo 'Refusing cleanup because unrecognized public tables exist:' >&2
  printf '%s\n' "$unknown_tables" >&2
  exit 1
fi

echo '===== ACCOUNTS THAT WILL BE REMOVED ====='
db_psql -P pager=off -c "SELECT username, id, created_at FROM users ORDER BY created_at, username"
echo '===== CURRENT APPLICATION ROW COUNTS ====='
db_psql -P pager=off <<'SQL'
SELECT format('SELECT %L AS table_name, count(*) AS row_count FROM %I.%I;', tablename, schemaname, tablename)
FROM pg_tables
WHERE schemaname = 'public' AND tablename <> 'alembic_version'
ORDER BY tablename
\gexec
SQL
echo '===== CURRENT ENCRYPTED FILE STORAGE ====='
find "$FILES_DIR" -mindepth 1 -maxdepth 1 -printf '%y %f\n' | sed -n '1,200p'
file_count="$(find "$FILES_DIR" -mindepth 1 -maxdepth 1 -type f -printf . | wc -c)"
file_bytes="$(find "$FILES_DIR" -xdev -type f -printf '%s\n' | awk '{n += $1} END {print n + 0}')"
echo "Regular files: $file_count; bytes: $file_bytes"

if [[ "$MODE" == --preview ]]; then
  echo 'Preview complete. Nothing was changed.'
  exit 0
fi
if [[ "${AKFES_CONFIRM_DELETE_ALL_TEST_DATA:-}" != 'DELETE-ALL-AKFES-TEST-DATA' ]]; then
  echo 'Execution confirmation is missing or incorrect.' >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$ROOT/backups/test-data-cleanup-$STAMP"
[[ ! -e "$DEST" && ! -L "$DEST" ]] || { echo "Backup destination already exists: $DEST" >&2; exit 1; }
install -d -o root -g root -m 0700 -- "$DEST"

services_were_stopped=false
files_were_moved=false
database_was_cleaned=false
resume_services() {
  if [[ "$services_were_stopped" == true ]]; then
    docker compose up -d api grants auth >/dev/null || true
  fi
}
rollback_files_if_needed() {
  if [[ "$files_were_moved" == true && "$database_was_cleaned" == false ]]; then
    if [[ -d "$FILES_DIR" && ! -L "$FILES_DIR" ]] && ! find "$FILES_DIR" -mindepth 1 -print -quit | grep -q .; then
      rmdir -- "$FILES_DIR"
      mv -- "$DEST/encrypted-files-active-directory" "$FILES_DIR"
      files_were_moved=false
      echo 'Encrypted-file directory was restored because database cleanup did not complete.' >&2
    else
      echo 'Automatic encrypted-file rollback was unsafe; use the backup directory shown above.' >&2
    fi
  fi
}
on_exit() {
  status=$?
  if [[ $status -ne 0 ]]; then rollback_files_if_needed; fi
  resume_services
  exit "$status"
}
trap on_exit EXIT

echo 'Stopping only the API and authentication services for a consistent backup...'
docker compose stop auth api >/dev/null
services_were_stopped=true

echo "Creating recoverable backup: $DEST"
docker compose exec -T db sh -ec '
  export PGPASSWORD="$POSTGRES_API_PASSWORD"
  exec pg_dump -U akfes_api -d akfes -Fc
' > "$DEST/postgres.dump"
[[ -s "$DEST/postgres.dump" ]] || { echo 'Database backup is empty.' >&2; exit 1; }
docker compose exec -T db pg_restore -l < "$DEST/postgres.dump" >/dev/null

tar --numeric-owner --one-file-system -C "$DATA_ROOT" -czf "$DEST/encrypted-files.tar.gz" files
[[ -s "$DEST/encrypted-files.tar.gz" ]] || { echo 'Encrypted-files backup is empty.' >&2; exit 1; }
tar -tzf "$DEST/encrypted-files.tar.gz" >/dev/null
sha256sum "$DEST/postgres.dump" "$DEST/encrypted-files.tar.gz" > "$DEST/SHA256SUMS"

files_uid="$(stat -c %u -- "$FILES_DIR")"
files_gid="$(stat -c %g -- "$FILES_DIR")"
files_mode="$(stat -c %a -- "$FILES_DIR")"
mv -- "$FILES_DIR" "$DEST/encrypted-files-active-directory"
files_were_moved=true
install -d -o "$files_uid" -g "$files_gid" -m "$files_mode" -- "$FILES_DIR"

cleanup_tables="$(db_psql -Atqc "SELECT string_agg(format('%I', tablename), ', ' ORDER BY tablename) FROM pg_tables WHERE schemaname='public' AND tablename IN ($allowed_tables_sql) AND tablename <> 'alembic_version'")"
[[ -n "$cleanup_tables" ]] || { echo 'No recognized application tables found.' >&2; exit 1; }
db_psql -c "BEGIN; TRUNCATE TABLE $cleanup_tables RESTART IDENTITY CASCADE; COMMIT;"
database_was_cleaned=true

echo '===== POST-CLEANUP VERIFICATION ====='
remaining_rows="$(db_psql -Atqc "SELECT (SELECT count(*) FROM users) + (SELECT count(*) FROM devices) + (SELECT count(*) FROM conversations) + (SELECT count(*) FROM messages) + (SELECT count(*) FROM encrypted_files)")"
[[ "$remaining_rows" == 0 ]] || { echo "Core rows remain after cleanup: $remaining_rows" >&2; exit 1; }
[[ -z "$(find "$FILES_DIR" -mindepth 1 -print -quit)" ]] || { echo 'Active encrypted-files directory is not empty.' >&2; exit 1; }

resume_services
services_were_stopped=false
for attempt in $(seq 1 30); do
  if curl -fsS --max-time 3 http://127.0.0.1:18001/health/ready >/dev/null \
    && curl -fsS --max-time 3 http://127.0.0.1:18003/health/ready >/dev/null; then
    break
  fi
  if [[ "$attempt" -eq 30 ]]; then
    echo 'Data cleanup succeeded, but a service did not become ready. The backup is intact.' >&2
    exit 1
  fi
  sleep 2
done

echo 'All AKFES test accounts and application data were removed.'
echo "Recovery backup: $DEST"
echo 'Schema, migrations, server configuration, TLS/JWT/Arduino secrets, and registration invite were preserved.'
