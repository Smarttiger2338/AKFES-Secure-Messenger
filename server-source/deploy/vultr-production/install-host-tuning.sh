#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
SOURCE=/opt/akfes/app/deploy/vultr-production/90-akfes-redis.conf
TARGET=/etc/sysctl.d/90-akfes-redis.conf
[[ -f "$SOURCE" ]] || { echo "Missing sysctl source: $SOURCE" >&2; exit 1; }
install -o root -g root -m 0644 "$SOURCE" "$TARGET"
sysctl --load "$TARGET"
[[ "$(sysctl -n vm.overcommit_memory)" == '1' ]] || { echo 'Failed to enable vm.overcommit_memory=1' >&2; exit 1; }
echo 'AKFES Redis host memory tuning applied.'
