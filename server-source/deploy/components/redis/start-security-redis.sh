#!/usr/bin/env sh
set -eu
: "${REDIS_SECURITY_AUTH_PASSWORD:?missing REDIS_SECURITY_AUTH_PASSWORD}"
: "${REDIS_SECURITY_API_PASSWORD:?missing REDIS_SECURITY_API_PASSWORD}"
: "${REDIS_SECURITY_NODE2_PASSWORD:?missing REDIS_SECURITY_NODE2_PASSWORD}"
mkdir -p /run/tls /run/redis-acl
cp /run/tls-ro/security-redis-server.crt /run/tls/security-redis-server.crt
cp /run/tls-ro/security-redis-server.key /run/tls/security-redis-server.key
cp /run/tls-ro/ca.crt /run/tls/ca.crt
cp /run/tls-ro/node1-api.crt /run/tls/node1-api.crt
cp /run/tls-ro/node1-api.key /run/tls/node1-api.key
chown -R redis:redis /run/tls
chmod 600 /run/tls/*.key
chmod 644 /run/tls/*.crt
ACL=/run/redis-acl/users.acl
umask 077
cat > "$ACL" <<ACL_EOF
user default off
user akfes_auth_sec on >${REDIS_SECURITY_AUTH_PASSWORD} \
  ~akfes:ratelimit:login:* ~akfes:ratelimit:register:* ~akfes:ratelimit:device-challenge:* ~akfes:ratelimit:arduino:* \
  ~akfes:device-pop:* ~akfes:arduino:* -@all +ping +get +set +getdel +incr +incrby +expire
user akfes_api_sec on >${REDIS_SECURITY_API_PASSWORD} \
  ~akfes:ratelimit:prekey-claim:* ~akfes:ratelimit:prekey-target:* ~akfes:ratelimit:user-search:* \
  ~akfes:ratelimit:file-upload:* ~akfes:ratelimit:file-download:* ~akfes:ratelimit:ws-message:* ~akfes:ratelimit:ws-connect:* \
  -@all +ping +get +set +getdel +incr +incrby +expire
user akfes_node2_sec on >${REDIS_SECURITY_NODE2_PASSWORD} \
  ~akfes:ratelimit:ws-message:* ~akfes:ratelimit:ws-connect:* -@all +ping +incr +incrby +expire
ACL_EOF
exec redis-server \
  --port 0 \
  --tls-port 6380 \
  --tls-cert-file /run/tls/security-redis-server.crt \
  --tls-key-file /run/tls/security-redis-server.key \
  --tls-ca-cert-file /run/tls/ca.crt \
  --tls-auth-clients yes \
  --aclfile "$ACL" \
  --appendonly yes --appendfsync everysec --save 60 1 \
  --maxmemory 96mb --maxmemory-policy noeviction \
  --protected-mode yes
