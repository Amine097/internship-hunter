FROM alpine:3.20
# base image is pinned to an Alpine release; its package set is the pin
# hadolint ignore=DL3018
RUN apk add --no-cache tinyproxy \
 && adduser -D -u 10002 egress
COPY docker/egress-proxy.sh /usr/local/bin/egress-proxy.sh
RUN chmod 0755 /usr/local/bin/egress-proxy.sh
USER egress
ENTRYPOINT ["/usr/local/bin/egress-proxy.sh"]
