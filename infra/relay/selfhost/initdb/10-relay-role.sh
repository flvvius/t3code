#!/bin/sh
# Runs once, on an empty data volume. The relay's role owns its database, so startup migrations
# work, but is not a superuser. The image may source this file, so it sets no shell options.
relay_password="$(cat /run/secrets/relay_db_password)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v relay_password="$relay_password" <<'SQL'
CREATE ROLE relay LOGIN PASSWORD :'relay_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER DATABASE relay OWNER TO relay;
REVOKE ALL ON DATABASE relay FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC;
SQL
unset relay_password
