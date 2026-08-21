# Self-contained hunt image: runtimes + gaslight itself, so a whole
# per-target run (sink + attacks + the target server) happens INSIDE one
# locked-down container. Sink and target share the container's loopback, so
# the SSRF/code-exec proofs work with `--network none` — loopback is up,
# the internet is not. No proxy, no second network (a simplification over
# the earlier host-sink + socat-proxy design).
#
# Build: docker build -f harness/hunt.Dockerfile -t gaslight-hunt .
#   (build context is the repo root so the source can be copied in)
#
# Layers onto gaslight-test-runner (node + python3 + uv/uvx + non-root
# runner uid 10001, built by harness/runner.Dockerfile) so no base image
# needs pulling — it only adds gaslight itself on top.
FROM gaslight-test-runner

USER root

# Install gaslight into a venv using uv (already on the base image; needs
# no pip/ensurepip, unlike python3 -m venv on the slim base).
COPY pyproject.toml /opt/gaslight/pyproject.toml
COPY README.md /opt/gaslight/README.md
COPY src /opt/gaslight/src
RUN uv venv /opt/gaslight/.venv \
    && uv pip install --python /opt/gaslight/.venv/bin/python /opt/gaslight \
    && mkdir -p /out && chown 10001:10001 /out

ENV PATH=/opt/gaslight/.venv/bin:$PATH
USER runner
WORKDIR /home/runner
