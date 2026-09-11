#!/bin/sh
# Destructive only to freshly created, uniquely named CI resources below.
set -eu
[ "${CI:-}" = true ] || { echo 'This disposable regression is CI-only.' >&2; exit 1; }
image=deepsnout-postgres:local
name="deepsnout-bootstrap-ci-$$"
network="$name-network"
data="$name-data"
secret="$name-secret"
cleanup() {
    status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then docker logs "$name" >&2 || true; fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm "$data" "$secret" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
docker network create "$network" >/dev/null
docker volume create "$data" >/dev/null
docker volume create "$secret" >/dev/null
set_password_file() {
    docker run --rm --entrypoint sh \
        --mount "type=volume,src=$secret,dst=/run/deepsnout-db" \
        -e "TEST_APP_PASSWORD=$1" "$image" -c \
        'printf %s "$TEST_APP_PASSWORD" > /run/deepsnout-db/password; chmod 444 /run/deepsnout-db/password'
}
start_db() {
    docker run -d --name "$name" --network "$network" --network-alias db \
        -e POSTGRES_USER=postgres -e POSTGRES_DB=deepsnout \
        -e POSTGRES_PASSWORD=bootstrap-ci-admin-only \
        --mount "type=volume,src=$data,dst=/var/lib/postgresql/data" \
        --mount "type=volume,src=$secret,dst=/run/deepsnout-db,readonly" \
        "$@" "$image" >/dev/null
}
query() {
    docker exec --user postgres "$name" psql -Xw -v ON_ERROR_STOP=1 \
        -h 127.0.0.1 -U postgres -d deepsnout -Atc "$1"
}
wait_db() {
    for i in $(seq 1 60); do
        if query 'SELECT 1' >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo 'Disposable PostgreSQL did not become ready.' >&2
    return 1
}
health() { docker exec --user postgres "$name" sh /usr/local/bin/deepsnout-db-healthcheck; }
bootstrap() { docker exec --user postgres "$name" sh /docker-entrypoint-initdb.d/001-app.sh; }

# Model a cluster whose standard initdb completed but the app script never ran.
# A quote in this disposable password also checks SQL-literal escaping.
set_password_file "bootstrap-ci-app-only'quote"
start_db --tmpfs /docker-entrypoint-initdb.d
wait_db
[ "$(query "SELECT count(*) FROM pg_roles WHERE rolname='deepsnout'")" = 0 ]
if health >/dev/null 2>&1; then echo 'Health passed with a missing app role.' >&2; exit 1; fi
query 'CREATE TABLE bootstrap_sentinel (value integer); INSERT INTO bootstrap_sentinel VALUES (42)' >/dev/null

# Recreating against the SAME volume does not replay the packaged init script.
docker stop "$name" >/dev/null
docker rm "$name" >/dev/null
start_db
wait_db
[ "$(query "SELECT count(*) FROM pg_roles WHERE rolname='deepsnout'")" = 0 ]
docker exec --user postgres "$name" test -r /docker-entrypoint-initdb.d/001-app.sh
bootstrap
health
before="$(query "SELECT rolpassword FROM pg_authid WHERE rolname='deepsnout'")"
bootstrap
[ "$before" = "$(query "SELECT rolpassword FROM pg_authid WHERE rolname='deepsnout'")" ]
[ "$(query 'SELECT value FROM bootstrap_sentinel')" = 42 ]
[ "$(query "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='deepsnout'")" = deepsnout ]
[ "$(query "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication FROM pg_roles WHERE rolname='deepsnout'")" = t ]

# Unlike pg_isready, the probe must reject wrong credentials. A bootstrap rerun
# must not silently reset an existing role to the wrong secret file either.
set_password_file wrong-ci-password
if health >/dev/null 2>&1; then echo 'Health passed with a wrong password.' >&2; exit 1; fi
bootstrap
[ "$before" = "$(query "SELECT rolpassword FROM pg_authid WHERE rolname='deepsnout'")" ]
if health >/dev/null 2>&1; then echo 'Bootstrap silently changed a live password.' >&2; exit 1; fi
set_password_file "bootstrap-ci-app-only'quote"
health
printf '%s\n' 'PostgreSQL bootstrap recovery, idempotence, preserved data and credential health checks passed.'
