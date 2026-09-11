#!/bin/sh
# Runs during first initialization, or explicitly to finish an interrupted one.
# Never drop data or change an existing role's password on a rerun.
(
set -eu
DEEPSNOUT_BOOTSTRAP_PASSWORD="$(cat /run/deepsnout-db/password)"
export DEEPSNOUT_BOOTSTRAP_PASSWORD
if [ -z "$DEEPSNOUT_BOOTSTRAP_PASSWORD" ]; then
    echo 'Application database password file is empty; refusing bootstrap.' >&2
    exit 1
fi
psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB:-deepsnout}" <<'SQL'
\getenv app_password DEEPSNOUT_BOOTSTRAP_PASSWORD
BEGIN;
SELECT format(
    'CREATE ROLE deepsnout LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deepsnout')
\gexec
ALTER DATABASE deepsnout OWNER TO deepsnout;
COMMIT;
SQL
)
