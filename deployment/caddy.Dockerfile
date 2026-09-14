FROM caddy:2.11.2-alpine
COPY --chmod=0644 deployment/Caddyfile /etc/caddy/Caddyfile
COPY --chmod=0755 deployment/caddy-entrypoint.sh /usr/local/bin/deepsnout-caddy
ENTRYPOINT ["/usr/local/bin/deepsnout-caddy"]
