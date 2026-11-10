#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/akfes
OUT="$ROOT/secrets/generated"
ENV_FILE="$ROOT/secrets/production.env"
[[ ! -e "$ENV_FILE" ]] || { echo "Refusing to overwrite existing secrets: $ENV_FILE" >&2; exit 1; }
command -v openssl >/dev/null || { echo 'openssl is required' >&2; exit 1; }
getent group akfesadmin >/dev/null || { echo 'akfesadmin group is required' >&2; exit 1; }

umask 077
mkdir -p "$OUT/pki" "$OUT/node1-db" "$OUT/node1-api" "$OUT/node1-auth" "$OUT/node1-security-redis" "$OUT/node2"
rand(){ openssl rand -base64 36 | tr -d '\n' | tr '/+' '_-'; }
sha256_hex(){ printf %s "$1" | openssl dgst -sha256 -r | awk '{print $1}'; }

POSTGRES_BOOTSTRAP_PASSWORD="$(rand)"
POSTGRES_API_PASSWORD="$(rand)"
POSTGRES_AUTH_PASSWORD="$(rand)"
POSTGRES_NODE2_PASSWORD="$(rand)"
REDIS_SECURITY_AUTH_PASSWORD="$(rand)"
REDIS_SECURITY_API_PASSWORD="$(rand)"
REDIS_SECURITY_NODE2_PASSWORD="$(rand)"
REDIS_REALTIME_AUTH_PASSWORD="$(rand)"
REDIS_REALTIME_API_PASSWORD="$(rand)"
REDIS_REALTIME_NODE2_PASSWORD="$(rand)"
REDIS_REALTIME_AUTH_PASSWORD_SHA256="$(sha256_hex "$REDIS_REALTIME_AUTH_PASSWORD")"
REDIS_REALTIME_API_PASSWORD_SHA256="$(sha256_hex "$REDIS_REALTIME_API_PASSWORD")"
REDIS_REALTIME_NODE2_PASSWORD_SHA256="$(sha256_hex "$REDIS_REALTIME_NODE2_PASSWORD")"
ARDUINO_MASTER_SECRET="$(openssl rand -hex 32)"
ADMIN_MFA_ENCRYPTION_KEY="$(openssl rand -hex 32)"
SECRET_KEY="$(openssl rand -hex 32)"
REGISTRATION_INVITE_CODE="$(rand)"
REGISTRATION_INVITE_SHA256="$(sha256_hex "$REGISTRATION_INVITE_CODE")"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$OUT/node1-auth/jwt-private.pem" >/dev/null 2>&1
openssl rsa -pubout -in "$OUT/node1-auth/jwt-private.pem" -out "$OUT/node1-auth/jwt-public.pem" >/dev/null 2>&1
cp "$OUT/node1-auth/jwt-public.pem" "$OUT/node1-api/jwt-public.pem"
cp "$OUT/node1-auth/jwt-public.pem" "$OUT/node2/jwt-public.pem"

openssl genrsa -out "$OUT/pki/ca.key" 3072 >/dev/null 2>&1
openssl req -x509 -new -key "$OUT/pki/ca.key" -sha256 -days 3650 \
  -subj '/CN=AKFES Vultr Internal CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out "$OUT/pki/ca.crt"
make_cert(){
  local name="$1" cn="$2" san="$3" eku="$4"
  openssl genrsa -out "$OUT/pki/${name}.key" 3072 >/dev/null 2>&1
  openssl req -new -key "$OUT/pki/${name}.key" -subj "/CN=${cn}" -out "$OUT/pki/${name}.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=%s\nextendedKeyUsage=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$san" "$eku" > "$OUT/pki/${name}.ext"
  openssl x509 -req -in "$OUT/pki/${name}.csr" -CA "$OUT/pki/ca.crt" -CAkey "$OUT/pki/ca.key" -CAcreateserial -days 825 -sha256 -extfile "$OUT/pki/${name}.ext" -out "$OUT/pki/${name}.crt" >/dev/null 2>&1
  rm -f "$OUT/pki/${name}.csr" "$OUT/pki/${name}.ext"
}
make_cert postgres-server postgres-server 'DNS:db' serverAuth
make_cert security-redis-server security-redis-server 'DNS:security-redis' serverAuth
make_cert redis-server redis-server 'DNS:realtime-redis,DNS:redis' serverAuth
make_cert node1-api akfes_api 'DNS:akfes-api' clientAuth
make_cert node1-auth akfes_auth 'DNS:akfes-auth' clientAuth
make_cert node2-api akfes_realtime_health 'DNS:akfes-realtime-health' clientAuth

for dir in node1-db node1-api node1-auth node1-security-redis node2; do cp "$OUT/pki/ca.crt" "$OUT/$dir/ca.crt"; done
cp "$OUT/pki/postgres-server."{crt,key} "$OUT/node1-db/"
cp "$OUT/pki/node1-api."{crt,key} "$OUT/node1-api/"
cp "$OUT/pki/node1-auth."{crt,key} "$OUT/node1-auth/"
cp "$OUT/pki/security-redis-server."{crt,key} "$OUT/node1-security-redis/"
cp "$OUT/pki/node1-api."{crt,key} "$OUT/node1-security-redis/"
cp "$OUT/pki/redis-server."{crt,key} "$OUT/node2/"
cp "$OUT/pki/node2-api."{crt,key} "$OUT/node2/"

cat > "$ENV_FILE" <<EOF
POSTGRES_BOOTSTRAP_PASSWORD=${POSTGRES_BOOTSTRAP_PASSWORD}
POSTGRES_API_PASSWORD=${POSTGRES_API_PASSWORD}
POSTGRES_AUTH_PASSWORD=${POSTGRES_AUTH_PASSWORD}
POSTGRES_NODE2_PASSWORD=${POSTGRES_NODE2_PASSWORD}
REDIS_SECURITY_AUTH_PASSWORD=${REDIS_SECURITY_AUTH_PASSWORD}
REDIS_SECURITY_API_PASSWORD=${REDIS_SECURITY_API_PASSWORD}
REDIS_SECURITY_NODE2_PASSWORD=${REDIS_SECURITY_NODE2_PASSWORD}
REDIS_REALTIME_AUTH_PASSWORD=${REDIS_REALTIME_AUTH_PASSWORD}
REDIS_REALTIME_API_PASSWORD=${REDIS_REALTIME_API_PASSWORD}
REDIS_REALTIME_NODE2_PASSWORD=${REDIS_REALTIME_NODE2_PASSWORD}
REDIS_REALTIME_AUTH_PASSWORD_SHA256=${REDIS_REALTIME_AUTH_PASSWORD_SHA256}
REDIS_REALTIME_API_PASSWORD_SHA256=${REDIS_REALTIME_API_PASSWORD_SHA256}
REDIS_REALTIME_NODE2_PASSWORD_SHA256=${REDIS_REALTIME_NODE2_PASSWORD_SHA256}
ARDUINO_MASTER_SECRET=${ARDUINO_MASTER_SECRET}
ADMIN_MFA_ENCRYPTION_KEY=${ADMIN_MFA_ENCRYPTION_KEY}
SECRET_KEY=${SECRET_KEY}
REGISTRATION_INVITE_SHA256=${REGISTRATION_INVITE_SHA256}
EOF
chown root:akfesadmin "$ENV_FILE"
chmod 640 "$ENV_FILE"
chmod 600 "$OUT"/*/*.key "$OUT/pki/ca.key"

INVITE_FILE="$ROOT/secrets/registration-invite.txt"
printf '%s\n' "$REGISTRATION_INVITE_CODE" > "$INVITE_FILE"
chmod 600 "$INVITE_FILE"
chown root:akfesadmin "$INVITE_FILE"
chmod 640 "$INVITE_FILE"
echo "Secrets created. Registration invite saved to: $INVITE_FILE"
echo 'Back up /opt/akfes/secrets offline. Do not copy it into a client package.'
