#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || { echo 'Usage: verify-backup.sh /opt/akfes/backups/<timestamp>' >&2; exit 2; }
backup_dir="$(readlink -f -- "$1")"
case "$backup_dir" in
  /opt/akfes/backups/*) ;;
  *) echo 'Backup path must be a generation below /opt/akfes/backups.' >&2; exit 2 ;;
esac
[[ -d "$backup_dir" && ! -L "$backup_dir" ]] || { echo 'Backup generation is missing or unsafe.' >&2; exit 1; }
for name in postgres.dump encrypted-files.tar.gz SHA256SUMS; do
  [[ -f "$backup_dir/$name" && ! -L "$backup_dir/$name" ]] || { echo "Missing backup artifact: $name" >&2; exit 1; }
done

(cd "$backup_dir" && sha256sum --check --strict SHA256SUMS)

cd /opt/akfes/app/deploy/vultr-production
docker compose exec -T db pg_restore --list < "$backup_dir/postgres.dump" >/dev/null

archive_entries="$(tar -tzf "$backup_dir/encrypted-files.tar.gz")"
[[ -n "$archive_entries" ]] || { echo 'Encrypted-file backup archive is empty.' >&2; exit 1; }
if grep -Eq '(^/|(^|/)\.\.(/|$))' <<<"$archive_entries"; then
  echo 'Encrypted-file backup contains an unsafe path.' >&2
  exit 1
fi
echo "PASS: backup generation is intact and structurally restorable: $backup_dir"
