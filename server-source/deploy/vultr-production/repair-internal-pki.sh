#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
ROOT=/opt/akfes
OUT="$ROOT/secrets/generated"
CA="$OUT/pki/ca.crt"
command -v openssl >/dev/null || { echo 'openssl is required' >&2; exit 1; }
install -d -o root -g root -m 0700 "$OUT/node1-api" "$OUT/node2"

# Realtime verifies JWTs but never receives the issuer private key. Keep the
# public verifier key synchronized for deployments created before Node2 was
# enabled as a separate service.
[[ -f "$OUT/node1-auth/jwt-public.pem" ]] || { echo 'JWT public key is missing from the auth service.' >&2; exit 1; }
install -m 0644 "$OUT/node1-auth/jwt-public.pem" "$OUT/node1-api/jwt-public.pem"
install -m 0644 "$OUT/node1-auth/jwt-public.pem" "$OUT/node2/jwt-public.pem"

# Python 3.13/OpenSSL rejects a CA certificate that has no keyUsage extension.
# Keep all application passwords, JWT keys and invitation data unchanged; only
# rotate this deployment's private service TLS hierarchy when the CA is legacy.
pki_valid(){
  [[ -f "$CA" ]] || return 1
  openssl x509 -in "$CA" -noout -ext keyUsage 2>/dev/null | grep -q 'Certificate Sign' || return 1
  local name
  for name in postgres-server security-redis-server redis-server node1-api node1-auth node2-api; do
    [[ -f "$OUT/pki/${name}.crt" && -f "$OUT/pki/${name}.key" ]] || return 1
    openssl verify -CAfile "$CA" "$OUT/pki/${name}.crt" >/dev/null 2>&1 || return 1
  done
  cmp -s "$CA" "$OUT/node1-db/ca.crt" && cmp -s "$CA" "$OUT/node1-api/ca.crt" \
    && cmp -s "$CA" "$OUT/node1-auth/ca.crt" && cmp -s "$CA" "$OUT/node1-security-redis/ca.crt" \
    && cmp -s "$CA" "$OUT/node2/ca.crt"
}
if pki_valid; then
  echo 'Internal TLS CA key usage is valid.'
  exit 0
fi

umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$ROOT/secrets/pki-backups/$stamp"
tmp="$(mktemp -d "$ROOT/secrets/.pki-repair.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
install -d -o root -g root -m 0700 "$backup"
if [[ -d "$OUT/pki" ]]; then
  cp -a "$OUT/pki" "$backup/"
fi

mkdir -p "$tmp/pki"
openssl genrsa -out "$tmp/pki/ca.key" 3072 >/dev/null 2>&1
openssl req -x509 -new -key "$tmp/pki/ca.key" -sha256 -days 3650 \
  -subj '/CN=AKFES Vultr Internal CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out "$tmp/pki/ca.crt"

make_cert(){
  local name="$1" cn="$2" san="$3" eku="$4"
  openssl genrsa -out "$tmp/pki/${name}.key" 3072 >/dev/null 2>&1
  openssl req -new -key "$tmp/pki/${name}.key" -subj "/CN=${cn}" -out "$tmp/pki/${name}.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=%s\nextendedKeyUsage=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$san" "$eku" > "$tmp/pki/${name}.ext"
  openssl x509 -req -in "$tmp/pki/${name}.csr" -CA "$tmp/pki/ca.crt" -CAkey "$tmp/pki/ca.key" \
    -CAcreateserial -days 825 -sha256 -extfile "$tmp/pki/${name}.ext" -out "$tmp/pki/${name}.crt" >/dev/null 2>&1
  openssl verify -CAfile "$tmp/pki/ca.crt" "$tmp/pki/${name}.crt" >/dev/null
  rm -f "$tmp/pki/${name}.csr" "$tmp/pki/${name}.ext"
}

make_cert postgres-server postgres-server 'DNS:db' serverAuth
make_cert security-redis-server security-redis-server 'DNS:security-redis' serverAuth
make_cert redis-server redis-server 'DNS:realtime-redis,DNS:redis' serverAuth
make_cert node1-api akfes_api 'DNS:akfes-api' clientAuth
make_cert node1-auth akfes_auth 'DNS:akfes-auth' clientAuth
make_cert node2-api akfes_realtime_health 'DNS:akfes-realtime-health' clientAuth

openssl x509 -in "$tmp/pki/ca.crt" -noout -ext keyUsage | grep -q 'Certificate Sign'
install -m 0600 "$tmp/pki/ca.key" "$OUT/pki/ca.key"
install -m 0644 "$tmp/pki/ca.crt" "$OUT/pki/ca.crt"
for name in postgres-server security-redis-server redis-server node1-api node1-auth node2-api; do
  install -m 0600 "$tmp/pki/${name}.key" "$OUT/pki/${name}.key"
  install -m 0644 "$tmp/pki/${name}.crt" "$OUT/pki/${name}.crt"
done

for dir in node1-db node1-api node1-auth node1-security-redis node2; do
  install -m 0644 "$tmp/pki/ca.crt" "$OUT/$dir/ca.crt"
done
install -m 0600 "$tmp/pki/postgres-server.key" "$OUT/node1-db/postgres-server.key"
install -m 0644 "$tmp/pki/postgres-server.crt" "$OUT/node1-db/postgres-server.crt"
install -m 0600 "$tmp/pki/node1-api.key" "$OUT/node1-api/node1-api.key"
install -m 0644 "$tmp/pki/node1-api.crt" "$OUT/node1-api/node1-api.crt"
install -m 0600 "$tmp/pki/node1-auth.key" "$OUT/node1-auth/node1-auth.key"
install -m 0644 "$tmp/pki/node1-auth.crt" "$OUT/node1-auth/node1-auth.crt"
install -m 0600 "$tmp/pki/security-redis-server.key" "$OUT/node1-security-redis/security-redis-server.key"
install -m 0644 "$tmp/pki/security-redis-server.crt" "$OUT/node1-security-redis/security-redis-server.crt"
install -m 0600 "$tmp/pki/node1-api.key" "$OUT/node1-security-redis/node1-api.key"
install -m 0644 "$tmp/pki/node1-api.crt" "$OUT/node1-security-redis/node1-api.crt"
install -m 0600 "$tmp/pki/redis-server.key" "$OUT/node2/redis-server.key"
install -m 0644 "$tmp/pki/redis-server.crt" "$OUT/node2/redis-server.crt"
install -m 0600 "$tmp/pki/node2-api.key" "$OUT/node2/node2-api.key"
install -m 0644 "$tmp/pki/node2-api.crt" "$OUT/node2/node2-api.crt"

touch "$ROOT/secrets/.pki-rotated"
echo "Repaired internal TLS PKI. Previous PKI backup: $backup"
