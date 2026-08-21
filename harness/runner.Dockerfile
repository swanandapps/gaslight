# Per-target isolation image for the Tier 2 hunt.
#
# Runs an untrusted, independently-built MCP server as a locked-down,
# non-root process. The actual containment (non-root user, --cap-drop=ALL,
# --read-only, no-internet network) is applied at `docker run` time by
# harness/hunt.py, not baked here — this image only CONTAINS the runtimes
# (node/npx for npm servers, python/uvx for PyPI servers) plus a
# writable-by-uid home the offline package cache lives in.
#
# Build: docker build -f harness/runner.Dockerfile -t gaslight-test-runner harness
FROM node:22-bookworm-slim

# uv/uvx for PyPI-published MCP servers; curl only to fetch the uv installer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 curl ca-certificates \
    && curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# A fixed non-root uid the run-time `--user 10001:10001` maps onto, with a
# home it can write its package cache into (mounted as a shared volume at run
# time, since the container root is --read-only).
RUN useradd --uid 10001 --create-home --home-dir /home/runner runner \
    && mkdir -p /home/runner/.npm /home/runner/.cache \
    && chown -R 10001:10001 /home/runner

ENV HOME=/home/runner
WORKDIR /home/runner
