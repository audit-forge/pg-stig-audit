#!/bin/sh
set -eu

# Generate local test cert/key for SSL checks
if [ ! -f "$PGDATA/server.key" ] || [ ! -f "$PGDATA/server.crt" ]; then
  openssl req -new -x509 -days 3650 -nodes -text \
    -subj "/CN=pg-hardened" \
    -keyout "$PGDATA/server.key" \
    -out "$PGDATA/server.crt"
  chown postgres:postgres "$PGDATA/server.key" "$PGDATA/server.crt"
  chmod 600 "$PGDATA/server.key"
  chmod 644 "$PGDATA/server.crt"
fi

# Try to enable pgaudit extension if package is available in image.
# (shared_preload_libraries is set via postgres -c flags)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='pgaudit') THEN
    CREATE EXTENSION IF NOT EXISTS pgaudit;
  END IF;
END $$;
SQL
