#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
SOURCE=/opt/akfes/app/deploy/vultr-production/Caddyfile
TARGET=/etc/caddy/Caddyfile
CANDIDATE=/etc/caddy/Caddyfile.akfes.new
BACKUP="/etc/caddy/Caddyfile.before-akfes.$(date -u +%Y%m%dT%H%M%SZ)"
WEB_SOURCE=/opt/akfes/app/web
WEB_TARGET=/var/www/akfes

[[ -f "$SOURCE" ]] || { echo "Missing source Caddyfile: $SOURCE" >&2; exit 1; }
[[ -f "$TARGET" ]] || { echo "Existing Caddyfile is missing: $TARGET" >&2; exit 1; }
[[ ! -L "$WEB_TARGET" ]] || { echo "Refusing symlink web root: $WEB_TARGET" >&2; exit 1; }
[[ ! -e "$WEB_TARGET" || -d "$WEB_TARGET" ]] || { echo "Web root is not a directory: $WEB_TARGET" >&2; exit 1; }
install -d -o root -g caddy -m 0755 "$WEB_TARGET"
[[ -f "$WEB_SOURCE/index.html" && ! -L "$WEB_SOURCE/index.html" && -s "$WEB_SOURCE/index.html" ]] || {
  echo "Missing or unsafe web entry point: $WEB_SOURCE/index.html" >&2
  exit 1
}
while IFS= read -r -d '' source_asset; do
  relative="${source_asset#"$WEB_SOURCE"/}"
  target_asset="$WEB_TARGET/$relative"
  [[ "$relative" != "$source_asset" && "$relative" != *'..'* ]] || { echo "Unsafe web asset path: $source_asset" >&2; exit 1; }
  [[ ! -L "$source_asset" && -s "$source_asset" ]] || { echo "Unsafe or empty web asset: $source_asset" >&2; exit 1; }
  install -d -o root -g caddy -m 0755 "$(dirname "$target_asset")"
  [[ ! -L "$target_asset" ]] || { echo "Refusing symlink web asset: $target_asset" >&2; exit 1; }
  [[ ! -e "$target_asset" || -f "$target_asset" ]] || { echo "Web asset target is not a file: $target_asset" >&2; exit 1; }
  install -o root -g caddy -m 0644 "$source_asset" "$target_asset"
done < <(find "$WEB_SOURCE" -type f -print0)
# Remove files from older content-addressed builds only when their relative
# source path no longer exists. This keeps the live web root an exact mirror
# instead of accumulating old JavaScript bundles and legacy entry files.
while IFS= read -r -d '' target_asset; do
  relative="${target_asset#"$WEB_TARGET"/}"
  [[ "$relative" != "$target_asset" && "$relative" != *'..'* ]] || { echo "Unsafe stale web path: $target_asset" >&2; exit 1; }
  if [[ ! -e "$WEB_SOURCE/$relative" ]]; then
    [[ -f "$target_asset" && ! -L "$target_asset" ]] || { echo "Refusing unsafe stale web target: $target_asset" >&2; exit 1; }
    rm -f -- "$target_asset"
  fi
done < <(find "$WEB_TARGET" -xdev -type f -print0)
find "$WEB_TARGET" -xdev -depth -mindepth 1 -type d -empty -delete
cp -a "$TARGET" "$BACKUP"
install -o root -g root -m 0644 "$SOURCE" "$CANDIDATE"
caddy fmt --overwrite "$CANDIDATE"
caddy validate --config "$CANDIDATE"
mv "$CANDIDATE" "$TARGET"
if systemctl is-active --quiet caddy; then caddy_action=reload; else caddy_action=start; fi
if ! systemctl "$caddy_action" caddy; then
  cp -a "$BACKUP" "$TARGET"
  if systemctl is-active --quiet caddy; then systemctl reload caddy || true; else systemctl start caddy || true; fi
  systemctl status caddy --no-pager --full || true
  journalctl -u caddy --no-pager -n 100 || true
  echo "Caddy $caddy_action failed; restored $BACKUP" >&2
  exit 1
fi
# Older releases retained raw client IP access logs for seven days. The new
# privacy boundary keeps application security audits but does not retain a
# general browsing history. Remove only the exact former regular log file.
OLD_ACCESS_LOG=/var/log/caddy/akfes-access.log
if [[ -L "$OLD_ACCESS_LOG" ]]; then
  echo "Refusing to remove symlink legacy access log: $OLD_ACCESS_LOG" >&2
  exit 1
elif [[ -f "$OLD_ACCESS_LOG" ]]; then
  rm -f -- "$OLD_ACCESS_LOG"
fi
echo "Caddy configuration installed. Previous config: $BACKUP"
