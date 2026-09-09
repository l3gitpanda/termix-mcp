# No native modules in the tree, so a single slim stage suffices and the
# install can run --ignore-scripts: the lockfile is the provenance control
# (all entries registry.npmjs.org with integrity hashes, asserted in CI).
FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app

# Fixed uid/gid so the data volume's ownership stays predictable across rebuilds.
RUN groupadd --gid 10001 mcp && useradd --uid 10001 --gid 10001 --create-home mcp

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# access-policy.schema.json is not documentation: access_policy_schema
# require()s it at ../../../ from src/mcp/tools/, so it must land at /app or
# that tool throws MODULE_NOT_FOUND in every container deploy. Over stdio the
# repo root supplies it, which is exactly why its absence here went unnoticed.
# test/smoke.mjs asserts this COPY covers every repo-root file src/ reaches for.
COPY healthcheck.mjs access-policy.schema.json ./
COPY src ./src
COPY scripts ./scripts

# The data volume (audit log) is mounted here; owned by the runtime user so the
# first boot can append without a chown on the host.
RUN mkdir -p /data && chown mcp:mcp /data
VOLUME ["/data"]

USER mcp
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "/app/healthcheck.mjs"]

# The container always runs the streamable-HTTP transport; stdio mode is for a
# workstation launching the process directly.
CMD ["node", "src/index-http.mjs"]
