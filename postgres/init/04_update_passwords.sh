#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -c "ALTER ROLE auth_app WITH PASSWORD '$AUTH_APP_PASSWORD'" \
  -c "ALTER ROLE audit_writer WITH PASSWORD '$AUDIT_WRITER_PASSWORD'" \
  -c "ALTER ROLE audit_reader WITH PASSWORD '$AUDIT_READER_PASSWORD'"
echo "Passwords updated"
