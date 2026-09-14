# Deployment and operator boundary

`docker compose up --build -d` provisions random application/DB secrets, PostgreSQL,
schema v1, the Python web/worker services and a bundled Caddy edge. Retrieve first-run
protection with `docker compose exec web deepsnout setup-token`, then create the
administrator in the GUI. Setup refuses to run again after an account exists.

Normal configuration, users, collection, retention jobs, expectations, demo removal
and investigation are GUI operations. Host installation, network firewalling,
infrastructure backup and disaster recovery remain host-administrator tasks. No
container shell/control is exposed by the web interface.

One worker only. Its PostgreSQL advisory lock excludes replicas. One web process
is also recommended; login throttling is process-local. Web/worker run as UID10001
with read-only root filesystems and dropped capabilities. Secret initialization
uses root only to create/chown files. PostgreSQL uses its standard container startup
in a thin derived image. Bootstrap scripts are copied into that image with explicit
read permissions; they are not bind-mounted from the host checkout. A separate
bootstrap admin secret is mounted only in the DB service; the application role is
not a PostgreSQL superuser and cannot create other databases or roles.

## Browser-facing HTTPS

The Compose deployment no longer publishes FastAPI directly. Caddy is the only
browser-facing service:

```text
browser -> TCP 80 (redirect only) / TCP+UDP 443 -> Caddy -> web:8000
                                                -> private Docker network
```

PostgreSQL is not published. The application service has no host port in the
standard Compose file.

Copy `.env.example` to `.env` and set the ONE DNS name or IP address that operators
will use in the browser:

```dotenv
DEEPSNOUT_PUBLIC_HOST=deepsnout.example.internal
DEEPSNOUT_ALLOWED_HOSTS=localhost,127.0.0.1,[::1]
DEEPSNOUT_SECURE_COOKIES=1
```

An IPv4 address is also valid; bracket an IPv6 literal. Do not put a URL, port,
space or comma in `DEEPSNOUT_PUBLIC_HOST`. The Caddy startup wrapper rejects values
that could become Caddyfile syntax.

Compose automatically adds `DEEPSNOUT_PUBLIC_HOST` to the application's Host
allowlist. `DEEPSNOUT_ALLOWED_HOSTS` is only for extra HTTP Host aliases. The current
Caddy configuration issues a certificate for one primary name/address, so extra
aliases do not automatically become valid TLS names.

Port 80 performs a permanent redirect to the corresponding HTTPS URL. Setup, login
and authenticated pages are therefore served through HTTPS in the Compose path.
`DEEPSNOUT_SECURE_COOKIES=1` is the deployment default.

### Bootstrap certificate

The first Caddy startup creates a persistent **DeepSnout Local CA** in the
`caddy-data` Docker volume and automatically issues/renews the leaf certificate for
`DEEPSNOUT_PUBLIC_HOST`. Caddy is explicitly told not to modify the container's own
trust stores. Trust on administrator workstations is an operator decision.

A browser will normally warn about the local CA until its public root is trusted.
For a short isolated pilot you can proceed through that warning according to local
policy. For deliberate trust distribution, export the public root only:

```sh
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > deepsnout-local-ca.crt
docker compose exec -T caddy sha256sum /data/caddy/pki/authorities/local/root.crt
```

Verify the fingerprint over a trusted channel before importing the CA on another
machine. The same public certificate is available over the already-TLS-protected
endpoint at `/deepsnout-local-ca.crt`, mainly as a convenience after the server
identity has been verified.

**Never export or distribute the Caddy local CA private key.** Any machine that
possesses it can mint certificates trusted by clients that trust this root.

The CA identity lives in `caddy-data`. Removing that volume creates a new CA on the
next start, invalidating trust you established in the old one. This is one reason
`docker compose down -v` is destructive, not a normal reset procedure.

### Organization certificates and ACME

The architecture deliberately keeps TLS ownership in Caddy rather than Uvicorn.
The current alpha does **not yet** provide GUI upload/activation of an organization
certificate or automatic public/internal ACME enrollment. Those are planned as
Caddy-management features; FastAPI will not be given normal read access to the
active TLS private key.

Until that management path is implemented, the supported bundled mode is the local
CA described above. Do not bake organization private keys into the application
Docker image. If a production environment requires its own TLS identity before the
integrated certificate manager exists, keep the deployment in a controlled pilot
scope or use an infrastructure-approved external TLS terminator rather than
modifying application code to disable TLS validation.

No SSO/MFA exists yet. HTTPS protects transport; it does not make an Internet-facing
pilot appropriate. Restrict ports 80/443 to the intended analyst/admin network.

## Health and retention

Operations shows heartbeat, queue/errors, row counts, missing process context,
libpsl availability and latest ingestion/maintenance reports. Minimum source
coverage is visible on findings. No input is not a clean endpoint verdict.
Tune explicit limits in Analysis policy; a failed slice does not advance a cursor.
A full queue/fingerprint cap requires investigation, not silent data dropping.

The web container still has an internal HTTP health check because that traffic
never leaves the Docker network. External Compose smoke tests verify the Caddy TLS
chain using the exported local root.

## Backups and recovery

Back up PostgreSQL, `app-secrets`, `db-secret` and `caddy-data` TOGETHER. The first
three contain sensitive application/DB state; `caddy-data` contains the DeepSnout
Local CA private key and certificate state. Losing only `caddy-data` does not erase
DeepSnout findings, but it changes the TLS trust identity and may break trusted
clients.

A logical database backup:

```sh
docker compose exec -T db pg_dump -U deepsnout -d deepsnout -Fc > deepsnout.dump
```

This alone is not a full backup. Preserve secret and Caddy volumes through
infrastructure backup, preferably with sources paused for a coherent snapshot.
Encrypt backups and test isolated restore. Unknown schema versions require an
explicit migration, not a blind init. GUI disaster-recovery restore is not
implemented.

Emergency host-admin account recovery:

```sh
docker compose exec web deepsnout reset-password --username admin
```

The interactive prompt avoids secrets in arguments. That account's sessions are
revoked and the action is audited. Normal changes are in Accounts.

## Offline, proxies and updates

Image builds need registry/package access. Prebuild and export/import the images
for disconnected deployment. The bundled local-CA Caddy runtime does not need
Internet access. No automatic reputation calls, downloads or model fetches run in
local analysis. The operator-configured Splunk connection is the intentional
collection dependency.

If the host requires an outbound proxy, Docker registry access and Dockerfile
`RUN` downloads are separate layers. Configure the daemon/builder as required or
preserve `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` through `sudo` and pass the standard
proxy build arguments. Do not put proxy credentials in the Dockerfiles.

The libpsl snapshot ages with the application image. Rebuild and scan dependencies
under normal change control; back up before updating. Direct Python dependencies
and the Caddy image tag are pinned, but transitive dependencies/base-image digests
are not a complete cryptographic lockfile. A future release should provide pinned
digests and reproducible offline bundles after the pilot is validated.

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
