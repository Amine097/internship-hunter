# Allow-listing CONNECT proxy of ONE agent (docker/egress_proxy.py, Python standard library only;
# docs/security-architecture.md, "Egress"). It replaces tinyproxy, which filtered the CONNECT
# hostname but could not see the TLS handshake (SNI) inside the tunnel.
# Pinned: the base by digest; the interpreter by its exact Alpine package version, so a rebuilt
# package fails the build instead of silently changing the proxy's runtime (to update: bump both,
# tests/test_cli_egress_policy.py asserts both).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
# `python` (unversioned) is removed on purpose: deploy/check-dns.sh picks its probe flavour by
# `command -v python`, and the proxies must keep providing the busybox `nslookup` positive control
# for internal-only services without Python (postgres). The proxy itself runs `python3 -IB`.
RUN apk add --no-cache python3=3.12.13-r0 \
 && rm -f /usr/bin/python \
 && adduser -D -u 10002 egress
COPY docker/egress-proxy.sh docker/egress-healthcheck.sh docker/egress-forbidden-check.sh /usr/local/bin/
COPY docker/egress_proxy.py /usr/local/bin/hunter-egress-proxy
RUN chmod 0755 /usr/local/bin/egress-proxy.sh /usr/local/bin/egress-healthcheck.sh \
 /usr/local/bin/egress-forbidden-check.sh /usr/local/bin/hunter-egress-proxy
USER egress
ENTRYPOINT ["/usr/local/bin/egress-proxy.sh"]
