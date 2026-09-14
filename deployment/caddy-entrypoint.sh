#!/bin/sh
set -eu

host="${DEEPSNOUT_PUBLIC_HOST:-localhost}"

# This value is substituted into a Caddyfile site address. Keep it to one
# hostname, IPv4 address, or bracketed IPv6 literal so an environment value
# cannot become Caddyfile syntax.
if ! printf '%s\n' "$host" | grep -Eq '^([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\])$'; then
    echo "Invalid DEEPSNOUT_PUBLIC_HOST. Use one hostname, IPv4 address, or bracketed IPv6 address." >&2
    exit 64
fi

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
