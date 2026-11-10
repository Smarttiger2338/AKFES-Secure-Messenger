#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/akfes
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$ROOT/backups/$STAMP"
mkdir -p "$DEST"
chmod 700 "$DEST"

cd "$ROOT/app/deploy/vultr-production"
set -a
source <(sed 's/\r$//' .env.production)
source <(sed 's/\r$//' "$ROOT/secrets/production.env")
source <(sed 's/\r$//' "$ROOT/app/release/docker-image-digests.env")
set +a

docker compose exec -T db pg_dump -U akfes_api -d akfes -Fc > "$DEST/postgres.dump"
tar --numeric-owner -C "$ROOT/data" -czf "$DEST/encrypted-files.tar.gz" files
sha256sum "$DEST/postgres.dump" "$DEST/encrypted-files.tar.gz" > "$DEST/SHA256SUMS"
"$ROOT/app/deploy/vultr-production/verify-backup.sh" "$DEST"
find "$ROOT/backups" -mindepth 1 -maxdepth 1 -type d -mtime +14 -print
echo "Backup created: $DEST"
echo 'The final find output is a dry-run list only; old backups are not deleted automatically.'
