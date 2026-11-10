#!/usr/bin/env bash
set -euo pipefail
: "${POSTGRES_API_PASSWORD:?missing POSTGRES_API_PASSWORD}"
: "${POSTGRES_AUTH_PASSWORD:?missing POSTGRES_AUTH_PASSWORD}"
: "${POSTGRES_NODE2_PASSWORD:?missing POSTGRES_NODE2_PASSWORD}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=api_password="$POSTGRES_API_PASSWORD" \
  --set=auth_password="$POSTGRES_AUTH_PASSWORD" \
  --set=node2_password="$POSTGRES_NODE2_PASSWORD" <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='akfes_api') THEN CREATE ROLE akfes_api LOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='akfes_auth') THEN CREATE ROLE akfes_auth LOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='akfes_node2') THEN CREATE ROLE akfes_node2 LOGIN; END IF;
END $$;
SELECT format('ALTER ROLE akfes_api PASSWORD %L', :'api_password') \gexec
SELECT format('ALTER ROLE akfes_auth PASSWORD %L', :'auth_password') \gexec
SELECT format('ALTER ROLE akfes_node2 PASSWORD %L', :'node2_password') \gexec
ALTER DATABASE akfes OWNER TO akfes_api;
GRANT CONNECT ON DATABASE akfes TO akfes_auth, akfes_node2;
GRANT USAGE ON SCHEMA public TO akfes_auth, akfes_node2;
ALTER ROLE akfes_auth SET default_transaction_read_only = off;
ALTER ROLE akfes_node2 SET default_transaction_read_only = on;
ALTER ROLE bootstrap_admin NOLOGIN;
SQL
