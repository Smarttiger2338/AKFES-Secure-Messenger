#!/usr/bin/env sh
set -eu
: "${REDIS_REALTIME_AUTH_PASSWORD_SHA256:?missing REDIS_REALTIME_AUTH_PASSWORD_SHA256}"
: "${REDIS_REALTIME_API_PASSWORD_SHA256:?missing REDIS_REALTIME_API_PASSWORD_SHA256}"
: "${REDIS_REALTIME_NODE2_PASSWORD_SHA256:?missing REDIS_REALTIME_NODE2_PASSWORD_SHA256}"
mkdir -p /run/tls /run/redis-acl
cp /run/tls-ro/redis-server.crt /run/tls/redis-server.crt
cp /run/tls-ro/redis-server.key /run/tls/redis-server.key
cp /run/tls-ro/ca.crt /run/tls/ca.crt
cp /run/tls-ro/node2-api.crt /run/tls/node2-api.crt
cp /run/tls-ro/node2-api.key /run/tls/node2-api.key
chown -R redis:redis /run/tls
chmod 600 /run/tls/*.key
chmod 644 /run/tls/*.crt
ACL=/run/redis-acl/users.acl
umask 077
cat > "$ACL" <<ACL_EOF
user default off
user akfes_auth_rt on #${REDIS_REALTIME_AUTH_PASSWORD_SHA256} &akfes:realtime:user:* -@all +ping +publish
user akfes_api_rt on #${REDIS_REALTIME_API_PASSWORD_SHA256} &akfes:realtime:user:* -@all +ping +publish
user akfes_node2_rt on #${REDIS_REALTIME_NODE2_PASSWORD_SHA256} &akfes:realtime:user:* -@all +ping +publish +subscribe +unsubscribe +psubscribe +punsubscribe
ACL_EOF
exec redis-server \
  --port 0 \
  --tls-port 6379 \
  --tls-cert-file /run/tls/redis-server.crt \
  --tls-key-file /run/tls/redis-server.key \
  --tls-ca-cert-file /run/tls/ca.crt \
  --tls-auth-clients yes \
  --aclfile "$ACL" \
  --appendonly yes --appendfsync everysec --save 60 1 \
  --maxmemory 128mb --maxmemory-policy noeviction \
  --protected-mode yes
