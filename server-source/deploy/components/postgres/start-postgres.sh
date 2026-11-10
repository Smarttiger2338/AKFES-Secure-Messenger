#!/bin/sh
set -eu
mkdir -p /var/lib/postgresql/zt-tls
cp /run/tls-ro/postgres-server.crt /var/lib/postgresql/zt-tls/server.crt
cp /run/tls-ro/postgres-server.key /var/lib/postgresql/zt-tls/server.key
cp /run/tls-ro/ca.crt /var/lib/postgresql/zt-tls/ca.crt
chown postgres:postgres /var/lib/postgresql/zt-tls/*
chmod 600 /var/lib/postgresql/zt-tls/server.key
chmod 644 /var/lib/postgresql/zt-tls/server.crt /var/lib/postgresql/zt-tls/ca.crt
exec /usr/local/bin/docker-entrypoint.sh "$@"
