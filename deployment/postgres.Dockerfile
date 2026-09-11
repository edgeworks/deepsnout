FROM postgres:17-bookworm
# Package bootstrap code instead of bind-mounting the host checkout. A restrictive
# host umask or SELinux label must not make it unreadable by the postgres user.
COPY --chmod=0644 deployment/postgres-init.sh /docker-entrypoint-initdb.d/001-app.sh
COPY --chmod=0644 deployment/postgres-healthcheck.sh /usr/local/bin/deepsnout-db-healthcheck
