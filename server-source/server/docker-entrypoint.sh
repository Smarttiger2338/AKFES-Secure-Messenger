#!/bin/sh
set -eu
SRC="${ZT_SECRET_MOUNT:-/run/zt-ro}"
DST="/run/zt"
if [ -d "$SRC" ]; then
  mkdir -p "$DST"
  # The source mount stays read-only. Copy secrets into a per-container tmpfs
  # so the application can run as an unprivileged user without widening the
  # host-side file permissions.
  cp -f "$SRC"/* "$DST"/ 2>/dev/null || true
  chown -R akfes:akfes "$DST"
  # Default copied material to owner-readable only, then selectively expose
  # public certificates/CA/JWT verification keys. This keeps jwt-private.pem
  # protected too; relying only on a *.key suffix would accidentally make it
  # world-readable inside the container.
  find "$DST" -type f -exec chmod 600 {} \;
  find "$DST" -type f \( -name '*.crt' -o -name '*.cer' -o -name 'ca.pem' -o -name 'jwt-public.pem' \) -exec chmod 644 {} \;
fi
exec gosu akfes "$@"
