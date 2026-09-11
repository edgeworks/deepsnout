#!/bin/sh
# pg_isready only tests server readiness, not a usable application login.
set -eu
PGPASSWORD="$(cat /run/deepsnout-db/password)"
export PGPASSWORD
[ -n "$PGPASSWORD" ] || exit 1
export PGCONNECT_TIMEOUT=3
# Use the service/network address: loopback can have trust authentication even
# when actual app connections require a password. The temporary init server is
# socket-only and must not make this probe pass before bootstrap has completed.
exec psql --no-psqlrc --no-password --set=ON_ERROR_STOP=1 \
    --host="${DEEPSNOUT_DB_HEALTH_HOST:-db}" --username=deepsnout \
    --dbname="${POSTGRES_DB:-deepsnout}" --tuples-only --no-align \
    --command='SELECT 1' >/dev/null
