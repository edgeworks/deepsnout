# Deployment and operator boundary

`docker compose up --build -d` provisions random application/DB secrets, PostgreSQL,
schema v1, web and one analysis worker. Retrieve first-run protection with
`docker compose exec web deepsnout setup-token`, then create the administrator in
the GUI. Setup refuses to run again after an account exists.

Normal configuration, users, collection, retention jobs, expectations, demo removal
and investigation are GUI operations. Host installation, TLS, infrastructure backup
and disaster recovery remain host-administrator tasks. No container shell/control
is exposed by the web interface.

One worker only. Its PostgreSQL advisory lock excludes replicas. One web process
is also recommended; login throttling is process-local. Web/worker run as UID10001
with read-only root filesystems and dropped capabilities. Secret initialization
uses root only to create/chown files. PostgreSQL uses its standard container startup in a thin derived image. Bootstrap
scripts are copied into that image with explicit read permissions; they are not
bind-mounted from the host checkout. A separate bootstrap admin secret
is mounted only in the DB service; the application role is not a PostgreSQL
superuser and cannot create other databases or roles.

## Network access

Default HTTP is loopback-only. Use SSH tunneling for evaluation or a trusted TLS
reverse proxy for shared operation. In .env:

```dotenv
DEEPSNOUT_ALLOWED_HOSTS=localhost,127.0.0.1,[::1],deepsnout.example.org
DEEPSNOUT_SECURE_COOKIES=1
```

Keep localhost for the internal health check. List hostnames, not origins or ports;
no wildcard. Preserve original Host at the proxy. Cookies are explicitly secure
rather than trusting arbitrary forwarded headers. Example NGINX location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    client_max_body_size 10m;
}
```

This is NOT a full TLS server configuration. Supply the organization's certificate
and restrict access to the intended analyst/admin network. No SSO/MFA exists yet.
A login page alone is not a reason to expose this pilot publicly.

## Health and retention

Operations shows heartbeat, queue/errors, row counts, missing process context,
libpsl availability and latest ingestion/maintenance reports. Minimum source
coverage is visible on findings. No input is not a clean endpoint verdict.
Tune explicit limits in Analysis policy; a failed slice does not advance a cursor.
A full queue/fingerprint cap requires investigation, not silent data dropping.

## Backups and recovery

Back up PostgreSQL, app-secrets and db-secret volumes TOGETHER. Both contain sensitive
material: DB metadata/password hashes/encrypted tokens and their encryption key.
A logical database backup:

```sh
docker compose exec -T db pg_dump -U deepsnout -d deepsnout -Fc > deepsnout.dump
```

This alone is not a full backup. Preserve both secret volumes through infrastructure backup,
preferably with sources paused for a coherent snapshot. Encrypt backups and test
isolated restore. Unknown schema versions require an explicit migration, not a
blind init. GUI disaster-recovery restore is not implemented.

Emergency host-admin account recovery:

```sh
docker compose exec web deepsnout reset-password --username admin
```

The interactive prompt avoids secrets in arguments. That account's sessions are
revoked and the action is audited. Normal changes are in Accounts.

## Offline and updates

Image builds need registry/package access. Prebuild and export/import the images
for disconnected deployment. No automatic reputation calls, downloads or model
fetches run in local analysis. The libpsl snapshot ages with the image. Rebuild and
scan dependencies under normal change control; back up before updating.
Direct dependencies are pinned, but transitive dependencies/base images are not a
complete cryptographic lockfile. A future release should provide pinned digests
and reproducible offline bundles after the initial container CI is validated.

## Interrupted PostgreSQL bootstrap: script permission denied

Earlier pilot versions bind-mounted `deployment/postgres-init.sh`. A host checkout
not readable by the container's `postgres` user (for example because of a restrictive
umask, ACL, or security label) can produce `001-app.sh: Permission denied`. This is
a read failure while sourcing the script, not simply a missing executable bit.
PostgreSQL may then restart with an existing cluster but no `deepsnout` login.
The upstream entrypoint deliberately does not rerun init scripts on an existing
cluster. Repeated restarts or correcting the file mode alone do not finish setup.

Current Compose builds `deepsnout-postgres:local` from
`deployment/postgres.Dockerfile`, packages the scripts with mode 0644, and verifies
an actual application connection/query for database health. The earlier
`pg_isready` probe could succeed even with a nonexistent application user.

For this specific interrupted initial installation, preserve all named volumes
and both existing secret sets. From the repository directory, run the following
steps individually; stop on any error. Prefix Docker commands with sudo when
required by your host. Back up first if you have already stored application data.

```sh
git pull --ff-only
docker compose stop web worker init
docker compose build db
docker compose up -d db
```

Wait until PostgreSQL reports `database system is ready to accept connections` in
`docker compose logs --tail=30 db`. It may remain *unhealthy* until its missing
application role is restored. Complete only the application bootstrap:

```sh
docker compose exec -T --user postgres db sh /docker-entrypoint-initdb.d/001-app.sh
docker compose exec -T --user postgres db sh /usr/local/bin/deepsnout-db-healthcheck
docker compose up --build -d
docker compose ps -a
docker compose exec web deepsnout setup-token
```

The bootstrap creates the app role only if absent, uses the existing mounted
application password, and assigns ownership of the dedicated `deepsnout` database.
It does not drop a database, table, volume, or existing role, and does not overwrite
an existing role's password. Successful reruns are idempotent. A password mismatch
is a separate recovery problem: restore a consistent DB/secret backup rather than
silently rotating credentials. Never post the password files or setup token.

Do NOT use `docker compose down -v` as a fix: it deletes persistent volumes.
The repair does not change the database major version or application schema.
