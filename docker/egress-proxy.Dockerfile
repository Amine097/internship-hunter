FROM alpine:3.24
# base image is pinned to an Alpine release; its package set is the pin
# hadolint ignore=DL3018
RUN apk add --no-cache tinyproxy \
 && adduser -D -u 10002 egress
COPY docker/egress-proxy.sh docker/egress-healthcheck.sh docker/egress-forbidden-check.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/egress-proxy.sh /usr/local/bin/egress-healthcheck.sh \
 /usr/local/bin/egress-forbidden-check.sh
USER egress
ENTRYPOINT ["/usr/local/bin/egress-proxy.sh"]
