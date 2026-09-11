#!/bin/sh
# The application owns only its dedicated database, never the cluster superuser.
(
set -eu
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set=app_password="$(cat /run/deepsnout-db/password)" <<'SQL'
CREATE ROLE deepsnout LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';
ALTER DATABASE deepsnout OWNER TO deepsnout;
SQL

)
