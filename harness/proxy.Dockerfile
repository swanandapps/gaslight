# Sink-reachability proxy for the isolated hunt.
#
# The target runs on a Docker network with NO route to the real internet, so
# it also can't reach gaslight's own local sink on the host. This tiny
# socat container sits on both that internal network and a second network
# that can reach host.docker.internal, forwarding one port straight through
# to the host's sink — the target's only reachable peer, nothing else.
#
# It must listen on the SAME port it forwards to, because the SSRF/code-exec
# attacks build "host:sink.port" uniformly for every host in loopback_hosts()
# (the proxy's network alias is passed via GASLIGHT_EXTRA_SINK_HOSTS).
#
# Build: docker build -f harness/proxy.Dockerfile -t gaslight-sink-proxy harness
FROM alpine:3.20
RUN apk add --no-cache socat
# SINK_PORT is supplied at run time; listen on it and forward to the same
# port on the host.
ENTRYPOINT ["sh", "-c", "exec socat TCP-LISTEN:${SINK_PORT},fork,reuseaddr TCP:host.docker.internal:${SINK_PORT}"]
